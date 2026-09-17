package io.jans.casa.authn;

import io.jans.service.cdi.util.CdiUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

public class IpChecker {

    private static final Logger logger = LoggerFactory.getLogger(IpChecker.class);

    // trustedNetworks: Map<String, List<String>> dominio -> lista de CIDRs
    // uid: email completo del usuario (ej: usuario@isciii.es)
    public static boolean isTrusted(Map<String, List<String>> trustedNetworks, String uid) {

        if (uid == null || !uid.contains("@")) {
            logger.warn("IpChecker: uid inválido o sin dominio: {}", uid);
            return false;
        }

        String domain = uid.substring(uid.indexOf("@") + 1).toLowerCase().trim();
        logger.info("IpChecker: dominio extraído del uid: {}", domain);

        if (trustedNetworks == null || !trustedNetworks.containsKey(domain)) {
            logger.info("IpChecker: dominio {} no tiene redes confiables configuradas", domain);
            return false;
        }

        List<String> cidrs = trustedNetworks.get(domain);
        String clientIp = getClientIp();
        logger.info("IpChecker: IP del cliente: {}, CIDRs para {}: {}", clientIp, domain, cidrs);

        if (clientIp == null) {
            logger.warn("IpChecker: no se pudo determinar la IP del cliente");
            return false;
        }

        for (String cidr : cidrs) {
            if (cidr != null && isInRange(clientIp, cidr.trim())) {
                logger.info("IpChecker: IP {} coincide con CIDR {} para dominio {}", clientIp, cidr, domain);
                return true;
            }
        }

        logger.info("IpChecker: IP {} NO está en ninguna red confiable para dominio {}", clientIp, domain);
        return false;
    }

    private static String getClientIp() {
        try {
            HttpServletRequest req = CdiUtil.bean(HttpServletRequest.class);
            if (req == null) return null;

            // 1. X-Real-IP (nginx: proxy_set_header X-Real-IP $remote_addr)
            String ip = req.getHeader("X-Real-IP");
            if (isValidIp(ip)) return ip.trim();

            // 2. X-Forwarded-For — primer elemento es la IP original del cliente
            String xff = req.getHeader("X-Forwarded-For");
            if (xff != null && !xff.trim().isEmpty()) {
                ip = xff.split(",")[0].trim();
                if (isValidIp(ip)) return ip;
            }

            // 3. RemoteAddr directo
            ip = req.getRemoteAddr();
            if (isValidIp(ip)) return ip.trim();

        } catch (Exception e) {
            logger.error("IpChecker: error obteniendo IP del cliente: {}", e.getMessage());
        }
        return null;
    }

    private static boolean isInRange(String ipStr, String cidr) {
        try {
            // IPv6 loopback → tratar como 127.0.0.1
            if ("::1".equals(ipStr) || "0:0:0:0:0:0:0:1".equals(ipStr)) {
                ipStr = "127.0.0.1";
            }
            // IPv4-mapped IPv6 (::ffff:192.168.1.1)
            if (ipStr.startsWith("::ffff:") || ipStr.startsWith("::FFFF:")) {
                ipStr = ipStr.substring(7);
            }

            int prefixLen = 32;
            String networkStr = cidr;

            if (cidr.contains("/")) {
                String[] parts = cidr.split("/");
                networkStr = parts[0].trim();
                prefixLen = Integer.parseInt(parts[1].trim());
            }

            long ipInt      = ipToLong(ipStr);
            long networkInt = ipToLong(networkStr);
            long mask       = prefixLen == 0 ? 0L : (0xFFFFFFFFL << (32 - prefixLen)) & 0xFFFFFFFFL;

            return (ipInt & mask) == (networkInt & mask);

        } catch (Exception e) {
            logger.warn("IpChecker: error evaluando CIDR {}: {}", cidr, e.getMessage());
            return false;
        }
    }

    private static long ipToLong(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) throw new IllegalArgumentException("IPv4 inválida: " + ip);
        long result = 0;
        for (String octet : octets) {
            int val = Integer.parseInt(octet.trim());
            if (val < 0 || val > 255) throw new IllegalArgumentException("Octeto inválido: " + val);
            result = (result << 8) | val;
        }
        return result;
    }

    private static boolean isValidIp(String ip) {
        return ip != null && !ip.trim().isEmpty() && !ip.equalsIgnoreCase("unknown");
    }

    private IpChecker() { }
}