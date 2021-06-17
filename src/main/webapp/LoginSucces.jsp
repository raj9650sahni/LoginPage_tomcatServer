<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Login Success Page</title>
</head>
<body>
<h3>Hi <%= request.getAttribute("user")  %>, Login Successful. </h3>
<a href="login.html"> Login Page</a>


</body>
</html>