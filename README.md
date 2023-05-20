# authclient
<p>The Sky-Auth Client Library, "authclient", is a Go package designed to provide a streamlined and efficient way to interact with the Sky-Auth Authentication server. This package provides an HTTP client along with associated methods and data types to handle the following functionalities:</p>
<ol>
  <li><strong>Service Account Registration:</strong> It provides the ability to register new service accounts. A service account is created with a specified name and a set of roles.</li>
  <li><strong>Service Account Authentication:</strong> The library can authenticate a service account using the account ID and secret key, returning a JWT token upon successful authentication.</li>
  <li><strong>User Authentication Verification:</strong> The library can verify the authentication status of a user using a provided JWT token. It sends a GET request to the '/is-authenticated' endpoint of the authentication server.</li>
  <li><strong>User Authorization Verification:</strong> The library can also verify a user's authorization to perform a specific action using a provided JWT token and a permission string.</li>
</ol>
<p>All the functionalities make use of the Sky-Auth Authentication server's API endpoints and expect responses in specific JSON formats.</p>
<p>It also comes with built-in error handling and provides custom error types for each function, such as <strong>CheckUserAuthorizationError</strong>, <strong>VerifyUserAuthenticationError</strong>, <strong>AuthenticateServiceAccountError</strong>, and <strong>RegisterServiceAccountError</strong>.</p>
<p>This library is designed to be simple, robust, and easily integratable into any Go project that needs to interact with the Sky-Auth Authentication server. It emphasizes on ease of use and readability while maintaining strong typing and error handling typical in Go codebases.</p>
