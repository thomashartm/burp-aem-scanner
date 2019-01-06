package burp.http;

import java.util.Map;

/**
 * Key value entry which represents a request parameter.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 01/2019
 */
public class Parameter<K, V> implements Map.Entry<K, V> {
    private K key;
    private V value;

    public Parameter(K key, V value) {
        this.key = key;
        this.value = value;
    }

    public K getKey() {
        return this.key;
    }

    public V getValue() {
        return this.value;
    }

    public K setKey(K key) {
        return this.key = key;
    }

    public V setValue(V value) {
        return this.value = value;
    }
}
