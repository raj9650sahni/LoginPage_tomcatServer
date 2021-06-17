package first;

import java.io.IOException;
import java.io.PrintWriter;
import java.rmi.ServerException;
import java.util.regex.Pattern;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(
	description = "Login Servlet Testing",
	urlPatterns = {"/LoginServlet"},
	initParams = {
			@WebInitParam(name ="user",value = "Raj"),
			@WebInitParam(name = "password",value="Raj@sahni20")
	}
)

public class LoginServelet extends HttpServlet {
	
	private static final String nameRegex ="^[A-Z]{1}[a-zA-Z]{2}[a-zA-Z]*";
	private static final String passwordRegex="^(?=.*[@#$%^&+=])(?=.*[0-9])(?=.*[A-Z]).{8,}$";
	@Override
	protected void doPost(HttpServletRequest request,HttpServletResponse response) throws ServerException ,IOException, ServletException {
		String user = request.getParameter("user");
		String pwd = request.getParameter("pwd");
		boolean validateUserName = validateFirstName(user);
		boolean userFirstName = userFirstName(request, response, validateUserName);
		boolean validatePassword = validatePassword(pwd);
		boolean userPassword = userPassword(request, response, validatePassword);
		String userID =getServletConfig().getInitParameter("user");
		String password = getServletConfig().getInitParameter("password");
		if (userFirstName == true ||  userPassword == true) {
			if (userID.equals(user) && password.equals(pwd)) {
				System.out.println("Login");
				request.setAttribute("user", user);
				request.getRequestDispatcher("LoginSucces.jsp").forward(request, response);
			} else {
				RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
				PrintWriter out = response.getWriter();
				out.println("<font>Incorrect Credentials</font>");
				rd.include(request, response);
			}
		}
	}

	private boolean userFirstName(HttpServletRequest request, HttpServletResponse response, boolean validateUserName)
			throws IOException, ServletException {
		if (validateUserName == false) {
			RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
			PrintWriter out = response.getWriter();
			out.println("<font>Incorrect Name Regex Pattern</font>");
			rd.include(request, response);
			return false;
		}
		return true;
	}
	
	private boolean userPassword(HttpServletRequest request, HttpServletResponse response, boolean validatePassword)
			throws IOException, ServletException {
		if (validatePassword == false) {
			RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
			PrintWriter out = response.getWriter();
			out.println("<font>Incorrect Password Regex Pattern</font>");
			rd.include(request, response);
			return false;
		}
		return true;
	}

	public boolean validateFirstName(String userName) {
		Pattern check = Pattern.compile(nameRegex);
		boolean value = check.matcher(userName).matches();
		return value;
	}
	
	public boolean validatePassword(String password) {
		Pattern check = Pattern.compile(passwordRegex);
		boolean value = check.matcher(password).matches();
		return value;
	}
}