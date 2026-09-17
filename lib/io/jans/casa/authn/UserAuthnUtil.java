package io.jans.casa.authn;

import io.jans.agama.model.*;
import io.jans.as.common.model.common.User;
import io.jans.as.server.service.*;
import io.jans.orm.PersistenceEntryManager;
import io.jans.service.cdi.util.CdiUtil;

import java.util.*;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuthnUtil {

    private static final Logger logger = LoggerFactory.getLogger(UserAuthnUtil.class);
    private static final MFAInfoHelper mfaInfo = new MFAInfoHelper();
    private static PersistenceEntryManager entryManager = CdiUtil.bean(PersistenceEntryManager.class);
    private static AuthenticationService authenticationService = CdiUtil.bean(AuthenticationService.class);

    private User user;
    private String uid;
    private String name;
    private String inum;
    private String preferredMethod;
    private boolean validCredentials;

    private String jsonLocation;
    private String jsonDevice;
    private List<String> policies = Collections.emptyList();

    // Mapa de dominio → configuracion AD
    // Clave: sufijo de dominio (ej: "@externos.isciii.es")
    // Valor: Map con server_url, base_dn, service_dn, service_password, user_attr,
    //        search_filter (opcional), connect_timeout (opcional)
    private Map<String, Object> adDomains = Collections.emptyMap();

    public UserAuthnUtil() { }

    public UserAuthnUtil(List<String> policies) {
        this.policies = policies;
        this.adDomains = loadAdDomains();
    }

    private static Map<String, Object> loadAdDomains() {

        try {
            String dn = "agFlowQname=io.jans.casa.authn.main,ou=flows,ou=agama,o=jans";
            AgamaFlowConfig flowConfig = entryManager.find(AgamaFlowConfig.class, dn);

            if (flowConfig == null || flowConfig.getMeta() == null) {
                logger.warn("No se encontro agFlowMeta para io.jans.casa.authn.main");
                return Collections.emptyMap();
            }

            com.fasterxml.jackson.databind.ObjectMapper mapper =
                    new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode root =
                    mapper.readTree(flowConfig.getMeta());

            com.fasterxml.jackson.databind.JsonNode adDomains =
                    root.path("properties").path("ad_domains");

            if (adDomains.isMissingNode() || adDomains.isNull()) {
                logger.info("No hay ad_domains configurados en agFlowMeta");
                return Collections.emptyMap();
            }

            Map<String, Object> result = new java.util.LinkedHashMap<>();
            adDomains.fields().forEachRemaining(domainEntry -> {
                Map<String, Object> cfgMap = new java.util.LinkedHashMap<>();
                domainEntry.getValue().fields().forEachRemaining(field ->
                    cfgMap.put(field.getKey(), field.getValue().asText())
                );
                result.put(domainEntry.getKey(), cfgMap);
            });

            logger.info("ad_domains cargados desde agFlowMeta: {}", result.keySet());
            return result;

        } catch (Exception e) {
            logger.error("Error cargando ad_domains desde agFlowMeta", e);
            return Collections.emptyMap();
        }

    }

    public void validate(String userName, String password) {

        logger.info("Validating password for {}", userName);

        // Intento 1: autenticación contra PostgreSQL (flujo habitual)
        if (authenticationService.authenticate(userName, password)) {
            loadAuthenticatedUser();
            return;
        }

        // Intento 2: fallback a AD si el dominio del usuario está configurado
        if (!adDomains.isEmpty() && userName != null && userName.contains("@")) {
            String domain = "@" + userName.substring(userName.indexOf("@") + 1);
            logger.debug("Autenticacion PostgreSQL fallida para {}. Buscando configuracion AD para dominio {}", userName, domain);

            for (Map.Entry<String, Object> entry : adDomains.entrySet()) {
                if (domain.equalsIgnoreCase(entry.getKey())) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> adConfig = (Map<String, Object>) entry.getValue();
                    logger.info("Intentando autenticacion AD para dominio {}", domain);
                    if (authenticateViaAD(userName, password, adConfig)) {
                        return;
                    }
                    break;
                }
            }
        }

    }

    // -----------
    // Autenticación contra Active Directory
    // -----------
    private boolean authenticateViaAD(String userName, String password, Map<String, Object> adConfig) {

        String serverUrl      = asString(adConfig.get("server_url"));
        String baseDn         = asString(adConfig.get("base_dn"));
        String serviceDn      = asString(adConfig.get("service_dn"));
        String servicePass    = asString(adConfig.get("service_password"));
        String userAttr       = asString(adConfig.get("user_attr"));
        String searchFilter   = asString(adConfig.get("search_filter"));
        String connectTimeout = "5000";

        Object timeout = adConfig.get("connect_timeout");
        if (timeout != null) {
            connectTimeout = timeout.toString();
        }

        // Extraer el valor de búsqueda según el atributo configurado
        String searchValue = userName;
        if ("sAMAccountName".equalsIgnoreCase(userAttr) && userName.contains("@")) {
            searchValue = userName.substring(0, userName.indexOf("@"));
            logger.debug("sAMAccountName extraido: {}", searchValue);
        }

        // Paso 1: buscar el DN del usuario con la cuenta de servicio
        String userDn = findUserDnInAD(serverUrl, baseDn, serviceDn, servicePass,
                                       userAttr, searchFilter, searchValue, connectTimeout);
        if (userDn == null) {
            logger.warn("Usuario {} no encontrado en el AD ({})", userName, serverUrl);
            return false;
        }

        // Paso 2: bind con el DN del usuario para validar credencial
        if (!bindAsUser(serverUrl, userDn, password, connectTimeout)) {
            logger.warn("Bind AD fallido para {}", userName);
            return false;
        }
        logger.info("Bind AD exitoso para {}", userName);

        // Paso 3: cargar usuario local desde PostgreSQL para sesión y 2FA
        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.getUserByAttribute("mail", userName);
        if (user == null) {
            user = userService.getUser(userName);
        }
        if (user == null) {
            logger.warn("Usuario {} autenticado en AD pero no existe en PostgreSQL local", userName);
            return false;
        }

        // Paso 4: establecer sesión en Jans sin revalidar password local
        if (!authenticationService.authenticate(user.getUserId())) {
            logger.warn("authenticationService.authenticate({}) devolvio false", user.getUserId());
            return false;
        }

        loadAuthenticatedUser();
        logger.info("Autenticacion AD completada para {}. uid={}", userName, uid);
        return true;

    }

    private void loadAuthenticatedUser() {
        user = authenticationService.getAuthenticatedUser();
        if (user != null) {
            validCredentials = true;
            uid = user.getUserId();
            inum = user.getAttribute("inum");
            name = Optional.ofNullable(user.getAttribute("displayName")).orElse(user.getAttribute("givenName"));
            preferredMethod = translate(user.getAttribute("jansPreferredMethod"));
            updatePolicies();
        }
    }

    // -----------
    // Métodos JNDI para acceso al AD
    // -----------
    private Hashtable<String, String> buildLdapEnv(String serverUrl, String bindDn, String bindPassword, String connectTimeout) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, serverUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, bindDn);
        env.put(Context.SECURITY_CREDENTIALS, bindPassword);
        env.put("com.sun.jndi.ldap.connect.timeout", connectTimeout);
        env.put("com.sun.jndi.ldap.read.timeout", connectTimeout);
        env.put(Context.REFERRAL, "ignore");
        return env;
    }

    private String findUserDnInAD(String serverUrl, String baseDn, String serviceDn,
                                   String servicePass, String userAttr, String searchFilter,
                                   String searchValue, String connectTimeout) {
        InitialDirContext ctx = null;
        try {
            ctx = new InitialDirContext(buildLdapEnv(serverUrl, serviceDn, servicePass, connectTimeout));

            String filter;
            if (searchFilter != null && !searchFilter.trim().isEmpty()) {
                filter = searchFilter.replace("%n", escapeLdapFilter(searchValue));
            } else {
                filter = String.format("(%s=%s)", userAttr, escapeLdapFilter(searchValue));
            }
            logger.debug("Filtro busqueda AD: {}", filter);

            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{ "dn" });
            controls.setCountLimit(1);

            NamingEnumeration<SearchResult> results = ctx.search(baseDn, filter, controls);
            if (results.hasMore()) {
                String userDn = results.next().getNameInNamespace();
                logger.debug("DN encontrado: {}", userDn);
                return userDn;
            }
            return null;

        } catch (AuthenticationException e) {
            logger.error("Cuenta de servicio no autenticada en AD: {}", e.getMessage());
            return null;
        } catch (CommunicationException e) {
            logger.error("No se pudo conectar al AD {}: {}", serverUrl, e.getMessage());
            return null;
        } catch (Exception e) {
            logger.error("Error inesperado buscando usuario en AD", e);
            return null;
        } finally {
            closeQuietly(ctx);
        }
    }

    private boolean bindAsUser(String serverUrl, String userDn, String password, String connectTimeout) {
        InitialDirContext ctx = null;
        try {
            ctx = new InitialDirContext(buildLdapEnv(serverUrl, userDn, password, connectTimeout));
            return true;
        } catch (AuthenticationException e) {
            logger.warn("Bind fallido (credencial incorrecta o cuenta bloqueada): {}", e.getMessage());
            return false;
        } catch (CommunicationException e) {
            logger.error("No se pudo conectar al AD para bind: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            logger.error("Error inesperado en bind: {}", e.getMessage());
            return false;
        } finally {
            closeQuietly(ctx);
        }
    }

    private void closeQuietly(InitialDirContext ctx) {
        if (ctx != null) {
            try { ctx.close(); } catch (Exception e) { /* ignorar */ }
        }
    }

    private String escapeLdapFilter(String value) {
        if (value == null) return "";
        return value
            .replace("\\", "\\5c")
            .replace("*",  "\\2a")
            .replace("(",  "\\28")
            .replace(")",  "\\29")
            .replace("\0", "\\00");
    }

    private String asString(Object value) {
        return value == null ? null : value.toString();
    }

    // -----------
    // Métodos públicos
    // -----------
    public String getUid() { return uid; }
    public String getName() { return name; }
    public String getInum() { return inum; }
    public boolean isValidCredentials() { return validCredentials; }
    public boolean isUser2FAOn() { return preferredMethod != null; }
    public void setJsonLocation(String jsonLocation) { this.jsonLocation = jsonLocation; }
    public void setJsonDevice(String jsonDevice) { this.jsonDevice = jsonDevice; }

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
        Set<String> methods = new LinkedHashSet<>();
        List<String> empty = Collections.emptyList();

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

        List<String> enrolled = mfaInfo.methodsEnrolled(inum);
        logger.info("User has enrollments for {}", enrolled);
        methods.retainAll(enrolled);
        logger.trace("Updated list of methods: {}", methods);

        List<String> result = new ArrayList<>();
        if (methods.remove(preferredMethod)) {
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

}
