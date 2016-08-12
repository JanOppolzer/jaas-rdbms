// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package com.tagish.auth;

import java.util.Map;
import java.util.*;
import java.sql.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Simple database based authentication module.
 *
 * @author Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * @version 1.0.3
 */
public class DBLogin extends SimpleLogin {
    protected String                dbDriver;
    protected String                dbURL;
    protected String                dbUser;
    protected String                dbPassword;
    protected String                userTable;
    protected String                where;
    protected String                userColumn;
    protected String                passColumn;



    protected synchronized Vector validateUser(String username, char password[]) throws LoginException{
        ResultSet rsu = null;
        Connection con = null;
        PreparedStatement psu = null;

        try {
            Class.forName(dbDriver);
            if (dbUser != null)
                con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            else
                con = DriverManager.getConnection(dbURL);

            psu = con.prepareStatement("SELECT " + passColumn + " FROM " + userTable + " WHERE " + userColumn + "=?" + where);

            psu.setString(1, username);
            rsu = psu.executeQuery();
            if (!rsu.next()) throw new FailedLoginException("Unknown user");
            String upwd = rsu.getString(1);
            String tpwd = null;
            String hpwd = null;
            String hAlg = null;
            String hash = null;
            try {
                Pattern p = Pattern.compile("^\\{[A-Za-z0-9\\-]+\\}");
                Matcher m = p.matcher(upwd);
                while (m.find()) {
                    String s = m.group();
                    int l = s.length();
                    l -= 1;
                    hAlg = s.substring(1,l);
                    hash = m.replaceFirst ("");
                }
            } catch (Exception e) {
                throw new LoginException ("Error reading password (" + e.getMessage() + ")");
            }
            try {
                tpwd = "{" + hAlg + "}";
                hpwd = new String(Utils.cryptPassword(password,hAlg));
                tpwd = tpwd.concat(hpwd);
            } catch (Exception e) {
                throw new LoginException("Error encoding password (" + e.getMessage() + ")");
            }
            if (!upwd.equals(tpwd)) throw new FailedLoginException("Incorrect password, hAlg: " + hAlg + ", hash: " + hash + ", password: " + hpwd);
            Vector p = new Vector();
            p.add(new TypedPrincipal(username, TypedPrincipal.USER));

            return p;
        } catch (ClassNotFoundException e) {
            throw new LoginException("Error reading user database (" + e.getMessage() + ")");
        } catch (SQLException e) {
            throw new LoginException("Error reading user database (" + e.getMessage() + ")");
        } finally {
            try {
                if (rsu != null) rsu.close();
                if (psu != null) psu.close();
                if (con != null) con.close();
            } catch (Exception e) { }
        }
    }

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
        super.initialize(subject, callbackHandler, sharedState, options);

        dbDriver = getOption("dbDriver", null);
        if (dbDriver == null) throw new Error("No database driver named (dbDriver=?)");
        dbURL = getOption("dbURL", null);
        if (dbURL == null) throw new Error("No database URL specified (dbURL=?)");
        dbUser = getOption("dbUser", null);
        dbPassword = getOption("dbPassword", null);
        if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
            throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

        userTable    = getOption("userTable",    "Users");
        userColumn   = getOption("userColumn", "user_name");
        passColumn   = getOption("passColumn", "user_password");
        where        = getOption("where",        "");

        if (null != where && where.length() > 0)
            where = " AND " + where;
        else
            where = "";
    }
}
