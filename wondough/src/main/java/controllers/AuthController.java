package wondough.controllers;

import java.util.*;
import java.net.*;
import java.io.*;
import java.sql.SQLException;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.HttpsURLConnection;

import spark.*;
import wondough.*;
import static wondough.SessionUtil.*;

public class AuthController {
    /** Serve the auth page (GET request) */
    public static Route serveAuthPage = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();

        String name = Program.getInstance().getDbConnection().lookupApp(Integer.parseInt(request.queryParams("app")));

        if(name == null) {
            response.status(400);
            return "Invalid appid.";
        }

        model.put("appname", name);
        model.put("target", request.queryParams("target"));

        return ViewUtil.render(request, model, "/velocity/auth.vm");
    };

    public static Route handleExchange = (Request request, Response response) -> {
        // retrieve the request token from the request
        String token = request.queryParams("token");

        String accessToken = Program.getInstance().getDbConnection().exchangeToken(token);

        if(accessToken == null) {
            response.status(400);
            return "Invalid request token.";
        }
        else {
            return accessToken;
        }
    };

    public static Route handleAuth = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();
        model.put("target", request.queryParams("target"));
        model.put("appname", request.queryParams("appname"));

        // retrieve the username and password from the request
        String username = request.queryParams("username");
        String password = request.queryParams("password");
        // make sure the username and password aren't empty
        if (username.isEmpty() || password.isEmpty()) {
            model.put("error", "Empty username or password!");
            return ViewUtil.render(request, model, "/velocity/auth.vm");
        }

		// find captcha response
		String captchaResponse = request.queryParams("g-recaptcha-response");

		// make sure captcha response exists
		if (captchaResponse == null) {
			model.put("error", "Captcha was not completed");
			return ViewUtil.render(request, model, "/velocity/recapauth.vm");
		}

		try {
			// create new http post request
			URL url = new URL("https://www.google.com/recaptcha/api/siteverify");
			HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
			con.setRequestMethod("POST");

			// send secret key and captcha response to google captch
			con.setDoOutput(true);
			DataOutputStream out = new DataOutputStream(con.getOutputStream());
			out.writeBytes(URLEncoder.encode("secret") + "=" + URLEncoder.encode("6Le9l38UAAAAAFStV195bY29PLs8LMI2dTOwezGP") + "&" + URLEncoder.encode("response") + "=" + captchaResponse);
			out.flush();
			out.close();

			// check response code is OK
			int status = con.getResponseCode();
			if (status != 200) {
				return null;
			}

			// read the input
			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer content = new StringBuffer();
			while ((inputLine = in.readLine()) != null) {
				content.append(inputLine);
			}
			in.close();
			con.disconnect();

			// convert input to json file
			JsonReader jsonReader = Json.createReader(new StringReader(content.toString()));
			JsonObject jsonObject = jsonReader.readObject();
			jsonReader.close();

			// if not successful, return an error
			if (jsonObject.getBoolean("success") != true) {
				model.put("error", "Please fill out the reCAPTCHA");
				return ViewUtil.render(request, model, "/velocity/auth.vm");
			}

		} catch (Exception e) {
			model.put("error", e.toString());
			return ViewUtil.render(request, model, "/velocity/auth.vm");
		}

		// try to find the user in the database
        WondoughUser user = null;

        try {
            user = Program.getInstance().getDbConnection().getUser(username);
            if(user == null) {
                model.put("error", "Incorrect Username or Password");
                return ViewUtil.render(request, model, "/velocity/auth.vm");
        	}
        } catch(SQLException ex) {
            model.put("error", ex.toString());
            return ViewUtil.render(request, model, "/velocity/auth.vm");
        }

		// retrieve global security configuration
		SecurityConfiguration config = Program.getInstance().getSecurityConfiguration();

        // hash the plain text password supplied by the client using the
        // security configuration for this particular user
        String hashedPassword = config.pbkdf2(password, user.getSalt(), user.getIterations(), user.getKeySize());

        // check that the hashed passwords match
        if(!user.getHashedPassword().equals(hashedPassword)) {
            model.put("error", "Incorrect Username or Password");
            return ViewUtil.render(request, model, "/velocity/auth.vm");
        }

        // check that the user's configuration is up-to-date;
        // if not, re-hash the password
        if(user.getIterations() != config.getIterations() ||
            user.getKeySize() != config.getKeySize()) {
				Program.getInstance().getDbConnection().updateUser(user.getUsername(), config.getIterations(), config.getKeySize(), config.pbkdf2(password, user.getSalt()));
        }

        // authorise an app
        WondoughApp app = null;

        try {
            // create an authorisation for this user
            app = Program.getInstance().getDbConnection().createApp(user);

            if(app == null) {
                model.put("error", "Couldn't authorise application!");
                return ViewUtil.render(request, model, "/velocity/auth.vm");
            }
        } catch(SQLException ex) {
            model.put("error", ex.toString());
            return ViewUtil.render(request, model, "/velocity/auth.vm");
        }
        // redirect the user somewhere, if this was requested
        if (getQueryLoginRedirect(request) != null) {
            // redirect to the target URL and append the token;
            // the token is hashed for security so that its
            // value cannot be read
			// make sure target URL is trusted
			if (getQueryLoginRedirect(request).equals("http://localhost:8080/oauth")) {
				response.redirect(
	                getQueryLoginRedirect(request) +
	                "?token=" + URLEncoder.encode(config.sha(app.getRequestToken())));
			} else {
				model.put("error", "URL redirect not trusted");
                return ViewUtil.render(request, model, "/velocity/auth.vm");
			}
        }

        return ViewUtil.render(request, model, "/velocity/auth.vm");
    };

}
