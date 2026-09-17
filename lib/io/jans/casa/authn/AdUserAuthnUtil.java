package io.jans.casa.authn;

import io.jans.agama.model.*;
import io.jans.as.common.model.common.User;
import io.jans.as.server.service.*;
import io.jans.orm.PersistenceEntryManager;
import io.jans.service.cdi.util.CdiUtil;

import java.util.*;

import javax.naming.Context;
import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// -----------
// Variante de UserAuthnUtil que valida credenciales contra Active Directory
// (bind LDAP) en lugar de PostgreSQL. El usuario debe existir igualmente en
// la base de datos local para cargar atributos, 2FA y politicas.
// La configuracion del AD llega desde el config del flujo Agama (conf.ad).
// -----------
public class AdUserAuthnUtil {

    private static final Logger logger = LoggerFactory.getLogger(AdUserAuthnUtil.class);
    private static final MFAInfoHelper mfaInfo = new MFAInfoHelper();
    private static PersistenceEntryManager entryManager = CdiUtil.bean(PersistenceEntryManager.class);

    private User user;
    private String uid;
    private String name;
    private String inum;
    private String preferredMethod;
    private boolean validCredentials;

    private String jsonLocation;
    private String jsonDevice;
    private List<String> policies = Collections.emptyList();

    // -----------
    // Configuracion del Active Directory (desde conf.ad del flujo)
    // -----------
    private String adServerUrl;
    private String adBaseDn;
    private String adServiceDn;
    private String adServicePassword;
    private String adUserAttr;
    private String adConnectTimeout = "5000";

    public AdUserAuthnUtil() { }

    public AdUserAuthnUtil(List<String> policies, Map<String, Object> adConfig) {

        this.policies = policies;

        adServerUrl = asString(adConfig.get("server_url"));
        adBaseDn = asString(adConfig.get("base_dn"));
        adServiceDn = asString(adConfig.get("service_dn"));
        adServicePassword = asString(adConfig.get("service_password"));
        adUserAttr = asString(adConfig.get("user_attr"));

        Object timeout = adConfig.get("connect_timeout");
        if (timeout != null) {
            if (timeout instanceof Number) {
                adConnectTimeout = String.valueOf(((Number) timeout).intValue());
            } else {
                adConnectTimeout = timeout.toString();
            }
        }

        logger.info("AdUserAuthnUtil inicializado. server_url={}, base_dn={}, user_attr={}",
                adServerUrl, adBaseDn, adUserAttr);

    }

    public void validate(String userName, String password) {

        logger.info("Validando password contra AD para {}", userName);

        if (userName == null || userName.trim().isEmpty()
                || password == null || password.isEmpty()) {
            logger.warn("Username o password vacios");
            return;
        }

        // -----------
        // Paso 1 - buscar el DN del usuario en el AD con la cuenta de servicio
        // -----------
        String userDn = findUserDnInAD(userName);
        if (userDn == null) {
            logger.warn("Usuario {} no encontrado en el AD", userName);
            return;
        }

        // -----------
        // Paso 2 - bind LDAP con el DN del usuario y su password
        // -----------
        if (!bindAsUser(userDn, password)) {
            logger.warn("Bind LDAP fallido para {}", userName);
            return;
        }
        logger.info("Bind en AD exitoso para {}", userName);

        // -----------
        // Paso 3 - cargar el usuario local desde la base de datos
        // (imprescindible para 2FA, politicas y atributos)
        // -----------
        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.getUserByAttribute("mail", userName);
        if (user == null) {
            user = userService.getUser(userName);
        }
        if (user == null) {
            logger.warn("Usuario {} autenticado en AD pero NO existe en la base de datos local", userName);
            return;
        }

        validCredentials = true;
        uid = user.getUserId();
        inum = user.getAttribute("inum");
        name = Optional.ofNullable(user.getAttribute("displayName")).orElse(user.getAttribute("givenName"));
        preferredMethod = translate(user.getAttribute("jansPreferredMethod"));
        updatePolicies();

        logger.info("Validacion AD completada para {}. uid={}", userName, uid);

    }

    public String getUid() {
        return uid;
    }

    public String getName() {
        return name;
    }

    public String getInum() {
        return inum;
    }

    public boolean isValidCredentials() {
        return validCredentials;
    }

    public boolean isUser2FAOn() {
         return preferredMethod != null;
    }

    public void setJsonLocation(String jsonLocation) {
        this.jsonLocation = jsonLocation;
    }

    public void setJsonDevice(String jsonDevice) {
        this.jsonDevice = jsonDevice;
    }

    public boolean prompt2FA() {

        boolean prompt = policies.isEmpty() || policies.contains("EVERY_LOGIN");
        if (prompt) return true;

        TrustedDevicesManager tdm = new TrustedDevicesManager(user, jsonDevice, jsonLocation);

        if (policies.contains("LOCATION_UNKNOWN")) {
            prompt = !tdm.knownLocation();
        }
        if (!prompt && policies.contains("DEVICE_UNKNOWN")) {
            prompt = !tdm.knownDevice();
        }
        if (!prompt) {
            logger.info("2FA will be skipped according to policy evaluation for this user");
        }
        return prompt;

    }

    public List<String> computeUserMethods(LinkedHashSet<String> supportedMethods) {

        logger.trace("Supported methods: {}", supportedMethods);
        Set<String> methods = new LinkedHashSet<>();    //preserve insertion order
        List<String> empty = Collections.emptyList();

        //Reduce the supported methods to those actually installed
        supportedMethods.forEach(meh -> {
            try {
                String dn = String.format("%s=%s,ou=flows,ou=agama,o=jans", Flow.ATTR_NAMES.QNAME, meh);

                if (entryManager.contains(dn, ProtoFlow.class)) {
                    methods.add(meh);
                }
            } catch (Exception e) {
                logger.error(e.getMessage());
            }
        });
        logger.trace("List of methods: {}", methods);

        if (methods.isEmpty()) {
            logger.info("None of {} exist as agama flows", supportedMethods);
            return empty;
        }

        //Filter only the methods that match registered credentials for the user
        List<String> enrolled = mfaInfo.methodsEnrolled(inum);
        logger.info("User has enrollments for {}", enrolled);
        methods.retainAll(enrolled);
        logger.trace("Updated list of methods: {}", methods);

        List<String> result = new ArrayList<>();
        if (methods.remove(preferredMethod)) {
            //Put the preferred on top
            result.add(preferredMethod);
        }
        result.addAll(methods);

        logger.info("Authentication methods list has been distilled to {}", result);
        return result;

    }

    public void updateTrustedDevices() {

        try {
            if (policies.isEmpty() || !isUser2FAOn()) return;

            TrustedDevicesManager tdm = new TrustedDevicesManager(user, jsonDevice, jsonLocation);
            tdm.updateDevices();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }

    }

    private void updatePolicies() {

        if (policies.contains("CUSTOM")) {
            String usrPolicy = user.getAttribute("jansStrongAuthPolicy");

            String[] policiesArr = usrPolicy == null ? new String[]{ "EVERY_LOGIN" } : usrPolicy.split(",\\s*");
            policies = List.of(policiesArr);
        }

    }

    private String translate(String oldAcr) {

        if (oldAcr == null) return null;

        if (!List.of("fido2", "super_gluu", "otp", "twilio_sms").contains(oldAcr)) return oldAcr;

        return "io.jans.casa.authn." + oldAcr;

    }

    // -----------
    // Metodos privados de acceso al Active Directory
    // -----------

    private Hashtable<String, String> buildLdapEnv(String bindDn, String bindPassword) {

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, adServerUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, bindDn);
        env.put(Context.SECURITY_CREDENTIALS, bindPassword);
        env.put("com.sun.jndi.ldap.connect.timeout", adConnectTimeout);
        env.put("com.sun.jndi.ldap.read.timeout", adConnectTimeout);
        env.put(Context.REFERRAL, "ignore");
        return env;

    }

    private String findUserDnInAD(String userName) {

        InitialDirContext ctx = null;
        try {
            ctx = new InitialDirContext(buildLdapEnv(adServiceDn, adServicePassword));

            String searchFilter = String.format("(%s=%s)", adUserAttr, userName);
            logger.debug("Filtro de busqueda AD: {}", searchFilter);

            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{ "dn" });
            controls.setCountLimit(1);

            NamingEnumeration<SearchResult> results = ctx.search(adBaseDn, searchFilter, controls);

            if (results.hasMore()) {
                SearchResult result = results.next();
                String userDn = result.getNameInNamespace();
                logger.debug("DN encontrado en AD: {}", userDn);
                return userDn;
            }
            return null;

        } catch (AuthenticationException e) {
            logger.error("La cuenta de servicio no pudo autenticarse en el AD: {}", e.getMessage());
            return null;
        } catch (CommunicationException e) {
            logger.error("No se pudo conectar al AD {}: {}", adServerUrl, e.getMessage());
            return null;
        } catch (Exception e) {
            logger.error("Error inesperado buscando usuario en AD", e);
            return null;
        } finally {
            closeQuietly(ctx);
        }

    }

    private boolean bindAsUser(String userDn, String password) {

        InitialDirContext ctx = null;
        try {
            ctx = new InitialDirContext(buildLdapEnv(userDn, password));
            return true;

        } catch (AuthenticationException e) {
            logger.warn("Bind fallido (credencial incorrecta o cuenta bloqueada): {}", e.getMessage());
            return false;
        } catch (CommunicationException e) {
            logger.error("No se pudo conectar al AD para bind: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            logger.error("Error inesperado en bind de usuario", e);
            return false;
        } finally {
            closeQuietly(ctx);
        }

    }

    private void closeQuietly(InitialDirContext ctx) {
        if (ctx != null) {
            try {
                ctx.close();
            } catch (Exception e) {
                // ignorar
            }
        }
    }

    private String asString(Object value) {
        return value == null ? null : value.toString();
    }

}
