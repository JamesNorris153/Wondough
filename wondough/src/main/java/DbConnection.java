package wondough;

import java.sql.*;

/**
* Represents a connection to the not-quite-as-volatile database.
* @author  The Intern
* @version 0.1
*/
public class DbConnection {
    /** The database connection to use. */
    private Connection connection;

    /**
    * Initialises a new database connection.
    * @param filename The name of the SQLite database file.
    */
    public DbConnection(String filename) throws SQLException {
        // construct the connection string
        String url = "jdbc:sqlite:" + filename;

        // connect to the database
        this.connection = DriverManager.getConnection(url);
    }

    /**
    * Retrieves the next User ID to use.
    */
    private int largestUserID() throws SQLException {
        Statement stmt = null;
        String query = "SELECT id FROM users ORDER BY id DESC LIMIT 1;";

        try {
            stmt = this.connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            if(rs.next()) {
                return rs.getInt("id") + 1;
            }
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (stmt != null) { stmt.close(); }
        }

        return 0;
    }

    /**
    * Retrieves the next request token ID to use.
    */
    private String nextRequestToken() {
		// passes to generateSalt method to produce random value
		SecurityConfiguration config = Program.getInstance().getSecurityConfiguration();
		return config.generateSalt();

    }

    /**
    * Retrieves the next access token ID to use.
    */
    private String nextAccessToken() {
		// passes to generateSalt method to produce random value
        SecurityConfiguration config = Program.getInstance().getSecurityConfiguration();
		return config.generateSalt();

    }

    /**
    * Inserts the specified user account into the database. This method
    * assumes that the ID of the user is not set to anything.
    * @param user The user account to insert.
    */
    public boolean createUser(WondoughUser user) throws SQLException {
		if (this.findUserByName(user.getUsername()) != null) {
			return false;
		}
        // get the next available ID for this user
        int id = this.largestUserID();

        // create a prepared statement to insert the user account
        // into the database
        PreparedStatement stmt = null;
        String query = "INSERT INTO users (id,username,password,salt,iterations,keySize) VALUES (?,?,?,?,?,?);";

        // try to insert the user into the database
        try {
            stmt = this.connection.prepareStatement(query);
            stmt.setInt(1, id);
			stmt.setString(2, user.getUsername());
			stmt.setString(3, user.getHashedPassword());
			stmt.setString(4, user.getSalt());
			stmt.setInt(5, user.getIterations());
			stmt.setInt(6, user.getKeySize());

			stmt.executeUpdate();
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (stmt != null) { stmt.close(); }
			return true;
        }
    }

	/**
    * Updates the specified user account in the database.
    * @param user The user account to update.
	* @param iterations The new iterations value to insert.
	* @param keySize The new keySize value to insert.
	* @param user The new hashedPassword value to insert.
    */
	public void updateUser(String username, int iterations, int keySize, String hashedPassword) throws SQLException {

		// create a prepared statement to insert the user account
        // into the database
		PreparedStatement stmt = null;
		String query = "UPDATE users SET iterations=?, keysize=?, password=? WHERE username =?";

		// try to update the user in the database
		try {
			stmt = this.connection.prepareStatement(query);
			stmt.setInt(1, iterations);
			stmt.setInt(2, keySize);
			stmt.setString(3, hashedPassword);
			stmt.setString(4, username);

			stmt.executeUpdate();
		} catch (SQLException e) {
			throw e;
		} finally {
			if (stmt != null) { stmt.close(); }
		}
	}

    /**
    * Looks up a user by their username.
    * @param username The username to lookup.
    */
    public WondoughUser getUser(String username) throws SQLException {

		// create a prepared statement to insert the user account
        // into the database
        PreparedStatement stmt = null;
        String query = "SELECT * FROM users WHERE username=? LIMIT 1;";

		// try to find the user in the database
        try {
            stmt = this.connection.prepareStatement(query);
            stmt.setString(1, username);

			ResultSet rs = stmt.executeQuery();

			// return user found
            if(rs.next()) {
                WondoughUser user = new WondoughUser(rs.getInt("id"), rs.getString("username"));
                user.setHashedPassword(rs.getString("password"));
                user.setSalt(rs.getString("salt"));
                user.setIterations(rs.getInt("iterations"));
                user.setKeySize(rs.getInt("keySize"));
                return user;
            }
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (stmt != null) { stmt.close(); }
        }

        return null;
    }

    /**
    * Looks up whether an app exists and returns the display name of the
    * application if successful.
    * @param id The ID of the application.
    */
    public String lookupApp(int id) throws SQLException {
        PreparedStatement stmt = null;
        String query = "SELECT name FROM apps WHERE appid=? LIMIT 1;";

        try {
            stmt = this.connection.prepareStatement(query);
            stmt.setInt(1, id);

            ResultSet rs = stmt.executeQuery();

            if(rs.next()) {
                return rs.getString("name");
            }
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (stmt != null) { stmt.close(); }
        }

        return null;
    }

    /**
    * Authorises a new application to perform actions on behalf
    * of the specified user.
    * @param user The user for whom the app should be registered.
    */
    public WondoughApp createApp(WondoughUser user) throws SQLException {
        PreparedStatement stmt = null;
        String query = "INSERT INTO authorised_apps (user,requestToken,accessToken) VALUES (?,?,?);";

        try {
            WondoughApp app = new WondoughApp(user.getID());
            app.setRequestToken(this.nextRequestToken());
            app.setAccessToken(this.nextAccessToken());

            stmt = this.connection.prepareStatement(query);
            stmt.setInt(1, user.getID());
            stmt.setString(2, app.getRequestToken());
            stmt.setString(3, app.getAccessToken());
            stmt.executeUpdate();

            return app;
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (stmt != null) { stmt.close(); }
        }
    }

    /**
    * Exchanges a request token for an access token.
    * @param requestToken The request token to exchange.
    */
    public String exchangeToken(String requestToken) throws SQLException {
        SecurityConfiguration config = Program.getInstance().getSecurityConfiguration();
        Statement stmt = null;
        String query = "SELECT requestToken, accessToken FROM authorised_apps;";

        try {
            stmt = this.connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            while(rs.next()) {
                String token = config.sha(rs.getString("requestToken"));

                if(token.equals(requestToken)) {
                    return config.sha(rs.getString("accessToken"));
                }
            }
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (stmt != null) { stmt.close(); }
        }

        return null;
    }

    /**
    * Validates whether the specified string is a valid access token and returns
    * the unique ID of the user it belongs to.
    * @param accessToken The access token to validate.
    */
    public Integer isValidAccessToken(String accessToken) throws SQLException {
        SecurityConfiguration config = Program.getInstance().getSecurityConfiguration();
        Statement stmt = null;
        String query = "SELECT user, accessToken FROM authorised_apps;";

        try {
            stmt = this.connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            while(rs.next()) {
                String token = config.sha(rs.getString("accessToken"));

                if(token.equals(accessToken)) {
                    return rs.getInt("user");
                }
            }
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (stmt != null) { stmt.close(); }
        }

        return null;
    }

    /**
    * Looks up a user by their username and returns their unique ID.
    * @param username The username to lookup.
    */
    public Integer findUserByName(String username) throws SQLException {
        PreparedStatement stmt = null;
        String query = "SELECT id FROM users WHERE username=? LIMIT 1;";

        try {
            stmt = this.connection.prepareStatement(query);
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();

            if(rs.next()) {
                return rs.getInt("id");
            }
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (stmt != null) { stmt.close(); }
        }

        return null;
    }

    /**
    * Creates a new transaction.
    * @param user The ID of the user sending the money.
    * @param recipient The ID of the recipient of the money.
    * @param description The description of the transaction.
    * @param amount The amount that is being transferred.
    */
    public boolean createTransaction(int user, int recipient, String description, float amount) throws SQLException {
        // don't allow users to send negative amounts
        if(amount < 0) {
            return false;
        }

		// get the balance for the user
		Transactions result = this.getTransactions(user);
		float total = result.getAccountBalance();

		// don't allow users to send more money than they have
		if (amount > total) {
			return false;
		}
		
        PreparedStatement creditStmt = null;
        PreparedStatement debitStmt = null;
        String creditQuery = "INSERT INTO transactions (uid,value,description) VALUES (?,?,?)";
        String debitQuery = "INSERT INTO transactions (uid,value,description) VALUES (?,?,?)";

        try {
            creditStmt = this.connection.prepareStatement(creditQuery);
            debitStmt = this.connection.prepareStatement(debitQuery);

            debitStmt.setInt(1, user);
            debitStmt.setFloat(2, -amount);
            debitStmt.setString(3, description);

            debitStmt.executeUpdate();

            creditStmt.setInt(1, recipient);
            creditStmt.setFloat(2, amount);
            creditStmt.setString(3, description);

            creditStmt.executeUpdate();

            return true;
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (creditStmt != null) { creditStmt.close(); }
            if (debitStmt != null) { debitStmt.close(); }
        }
    }

    /**
    * Gets all transactions for a user.
    * @param user The unique ID of the user to look up transactions for.
    */
    public Transactions getTransactions(int user) throws SQLException {
        PreparedStatement stmt = null;
        String query = "SELECT * FROM transactions WHERE uid=? ORDER BY tid DESC;";

        try {
            stmt = this.connection.prepareStatement(query);
            stmt.setInt(1, user);
            ResultSet rs = stmt.executeQuery();

            Transactions result = new Transactions();
            float total = 0.0f;

            while(rs.next()) {
                Transaction t = new Transaction(rs.getInt("tid"));
                t.setAmount(rs.getFloat("value"));
                t.setDescription(rs.getString("description"));
                result.addTransaction(t);

                total += t.getAmount();
            }

            result.setAccountBalance(total);

            return result;
        } catch (SQLException e ) {
            throw e;
        } finally {
            if (stmt != null) { stmt.close(); }
        }
    }

    /**
    * Closes the database connection.
    */
    public void close() throws SQLException {
        this.connection.close();
    }
}
