# AuthClient Library
<p>The AuthClient Client Library is a Go package designed to provide a streamlined and efficient way to interact with the Sky-Auth Authentication server. This package provides an HTTP client along with associated methods and data types to handle the following functionalities:</p>
<ol>
  <li><strong>Service Account Registration:</strong> It provides the ability to register new service accounts. A service account is created with a specified name and a set of roles.</li>
  <li><strong>Service Account Authentication:</strong> The library can authenticate a service account using the account ID and secret key, returning a JWT token upon successful authentication.</li>
  <li><strong>User Authentication Verification:</strong> The library can verify the authentication status of a user using a provided JWT token. It sends a GET request to the '/is-authenticated' endpoint of the authentication server.</li>
  <li><strong>User Authorization Verification:</strong> The library can also verify a user's authorization to perform a specific action using a provided JWT token and a permission string.</li>
</ol>
<p>All the functionalities make use of the Sky-Auth Authentication server's API endpoints and expect responses in specific JSON formats.</p>
<p>It also comes with built-in error handling and provides custom error types for each function, such as <strong>CheckUserAuthorizationError</strong>, <strong>VerifyUserAuthenticationError</strong>, <strong>AuthenticateServiceAccountError</strong>, and <strong>RegisterServiceAccountError</strong>.</p>
<p>This library is designed to be simple, robust, and easily integratable into any Go project that needs to interact with the Sky-Auth Authentication server. It emphasizes on ease of use and readability while maintaining strong typing and error handling typical in Go codebases.</p>

<h2>Installation</h2>
	
	go get github.com/PiccoloMondoC/sky-auth/pkg/clientlib/authclient

<h2>Usage</h2>
<p>Firstly, you need to create a new authclient.Client instance.</p>

	import "github.com/PiccoloMondoC/sky-auth/pkg/clientlib/authclient"

	client := authclient.NewClient(baseURL, logger)

Where:
<ul>
  <li>baseURL is the base URL of the SkyAuth server.</li>
  <li>logger is an instance of the logger from the "github.com/PiccoloMondoC/sky-auth/internal/logging" package.</li>
 </ul>
<p>If you want to specify a custom http.Client, you can pass it as the third argument to the NewClient function.</p>

<h2>Register a Service Account</h2>
	
	accountID, secret, err := client.RegisterServiceAccount(context.Background(), "account-name", []string{"role1", "role2"})
	if err != nil {
		// handle error
	}

<p>This function will register a new service account with the provided name and roles. The function will return the accountID and secret of the newly created account.</p>

<h2>Authenticate a Service Account</h2>
	token, err := client.AuthenticateServiceAccount(context.Background(), accountID, secret)
	if err != nil {
		// handle error
	}

<p>This function will authenticate a service account using its accountID and secretKey and return a JWT token if successful.</p>

<h2>Verify User Authentication</h2>

	isAuthenticated, err := client.VerifyUserAuthentication(context.Background(), token)
	if err != nil {
		// handle error
	}

<p>This function verifies a JWT token and returns a boolean value indicating whether the token is valid.</p>

<h2>Check User Authorization</h2>
	hasPermission, err := client.CheckUserAuthorization(context.Background(), token, "permission")
	if err != nil {
		// handle error
	}

<p>This function verifies a user's authorization to perform a certain action (specified by the permission argument) and returns a boolean value indicating whether the user has the required permissions.</p>

<h2>Error Handling</h2>
<p>All the functions will return an error in case of a failure. The returned errors will be of the following types:</p>
<ul>
  <li>CheckUserAuthorizationError</li>
  <li>VerifyUserAuthenticationError</li>
  <li>AuthenticateServiceAccountError</li>
  <liRegisterServiceAccountError</li>
<p>These are custom error types that contain the base error and the status code returned from the SkyAuth server.</p>
  <h2>Logging</h2>
  <p>All the operations are logged using the provided logger.</p>
