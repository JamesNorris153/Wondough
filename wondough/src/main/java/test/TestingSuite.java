package wondough;

import java.sql.*;

public class TestingSuite {

	// run all tests on startup
	public void runTests() {

		// create new user for testing
		SecurityConfiguration config = Program.getInstance().getSecurityConfiguration();
		WondoughUser hacker = new WondoughUser(-1, "hacker");
		hacker.setSalt(config.generateSalt());
		hacker.setHashedPassword(config.pbkdf2("1234", hacker.getSalt()));
		hacker.setIterations(config.getIterations());
		hacker.setKeySize(config.getKeySize());

		// test for each vulnerability
		this.vulnerability1(hacker);
		this.vulnerability2(hacker);
		this.vulnerability3();
		this.vulnerability4();
		this.vulnerability5();
		this.vulnerability6();
		this.vulnerability7();
		this.vulnerability8(hacker);
		this.vulnerability9();
		this.vulnerability10();

		// clean up after tests run
		try {
			this.cleanUp();
		} catch (SQLException e) {
			System.out.println("clean up completed with exception: " + e.toString());
		}

	}

	public void vulnerability1(WondoughUser hacker) {
		Vulnerability1 uno = new Vulnerability1();
		uno.test(hacker);
	}

	public void vulnerability2(WondoughUser hacker) {
		Vulnerability2 dos = new Vulnerability2();
		dos.test(hacker);
	}

	public void vulnerability3() {
		//Vulnerability3 tres = new Vulnerability3();
		//tres.test();
	}

	public void vulnerability4() {
		Vulnerability4 cuatro = new Vulnerability4();
		cuatro.test();
	}

	public void vulnerability5() {
		Vulnerability5 cinco = new Vulnerability5();
		cinco.test();
	}

	public void vulnerability6() {
		Vulnerability6 seis = new Vulnerability6();
		seis.test();
	}

	public void vulnerability7() {
		Vulnerability7 siete = new Vulnerability7();
		siete.test();
	}

	public void vulnerability8(WondoughUser hacker) {
		Vulnerability8 ocho = new Vulnerability8();
		ocho.test(hacker);
	}

	public void vulnerability9() {
		Vulnerability9 nueve = new Vulnerability9();
		nueve.test();
	}

	public void vulnerability10() {
		Vulnerability10 diez = new Vulnerability10();
		diez.test();
	}

	// clean up data left over
	private void cleanUp() throws SQLException {
		String url = "jdbc:sqlite:" + "wondough.db";
		Connection connection = DriverManager.getConnection(url);

		Statement stmt = null;
		String query = "DELETE FROM authorised_apps WHERE user=-1";
		try {
            stmt = connection.createStatement();
            stmt.executeUpdate(query);

			query = "DELETE FROM users WHERE username='hacker'";
			stmt = connection.createStatement();
			stmt.executeUpdate(query);

			query = "DELETE FROM users WHERE username='sqlHacker'";
			stmt = connection.createStatement();
			stmt.executeUpdate(query);

			query = "DELETE FROM users WHERE username='victim'";
			stmt = connection.createStatement();
			stmt.executeUpdate(query);

			query = "DELETE FROM users WHERE username='user1'";
			stmt = connection.createStatement();
			stmt.executeUpdate(query);

			query = "DELETE FROM users WHERE username='user2'";
			stmt = connection.createStatement();
			stmt.executeUpdate(query);

			query = "DELETE FROM transactions WHERE description='test'";
			stmt = connection.createStatement();
			stmt.executeUpdate(query);

        } catch (SQLException e) {
         	System.out.println("Cleanup failed" + e.toString());
        } finally {
            if (stmt != null) { stmt.close(); }
        }
	}
}
