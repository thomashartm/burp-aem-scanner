package legacy.payload;

/**
 * Provides the AEM default credentials for build in users
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public enum DefaultCredential {

    ADMIN("admin", "admin"),
    REPLICATION("replication-receiver", "replication-receiver"),
    VGNADMIN("vgnadmin", "vgnadmin"),
    AUTHOR("author", "author"),
    APARKER("aparker@geometrixx.info", "aparker"),
    JDOE("jdoe@geometrixx.info", "jdoe");

    private String userName;

    private String password;

    DefaultCredential(final String userName, final String password) {
        this.userName = userName;
        this.password = password;
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public String getCombination() {
        return String.format("%s:%s", this.userName, this.password);
    }
}
