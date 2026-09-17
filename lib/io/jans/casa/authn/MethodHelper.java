package io.jans.casa.authn;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

public class MethodHelper {

    /**
     * Returns the first element of a "methods" container coming from Agama/Rhino.
     * Supports:
     *  - Collection (List/Set/etc.)
     *  - Java arrays (Object[] / String[] / etc.)
     *  - Rhino/JS-like maps or objects (best-effort)
     *  - Fallback: returns String.valueOf(obj)
     *
     * @param obj container or value
     * @return first element as String, or null if empty/unsupported
     */
    public static String first(Object obj) {

        if (obj == null) {
            return null;
        }

        // 1) Java Collection (List, Set, LinkedHashSet, etc.)
        if (obj instanceof Collection) {
            Collection<?> col = (Collection<?>) obj;
            if (col.isEmpty()) {
                return null;
            }
            Iterator<?> it = col.iterator();
            return it.hasNext() ? String.valueOf(it.next()) : null;
        }

        // 2) Java arrays (Object[], String[], primitive arrays, etc.)
        Class<?> cls = obj.getClass();
        if (cls.isArray()) {
            int len = Array.getLength(obj);
            if (len <= 0) {
                return null;
            }
            Object first = Array.get(obj, 0);
            return first != null ? String.valueOf(first) : null;
        }

        // 3) Sometimes Rhino objects may behave like Map
        // (depends on how the engine wraps/unwraps values)
        if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;

            // If it's a map with numeric keys like 0, "0", etc.
            Object v = null;
            if (map.containsKey(0)) {
                v = map.get(0);
            } else if (map.containsKey("0")) {
                v = map.get("0");
            }

            if (v != null) {
                return String.valueOf(v);
            }

            // As a fallback, return first entry's value
            if (!map.isEmpty()) {
                Object anyVal = map.values().iterator().next();
                return anyVal != null ? String.valueOf(anyVal) : null;
            }

            return null;
        }

        // 4) Fallback: if obj is already a single method name
        // (e.g. "otp", "fido2", etc.)
        return String.valueOf(obj);
    }
}
