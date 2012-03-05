This is a pure Ruby implementation of the Secure Remote Password protocol (SRP-6a). SRP is a cryptographically strong authentication protocol for password-based, mutual authentication over an insecure network connection.

Unlike other common challenge-response autentication protocols, such as Kereros and SSL, SRP does not rely on an external infrastructure of trusted key servers or certificate management. Instead, SRP server applications use verification keys derived from each user's password to determine the authenticity of a network connection.

SRP provides mutual-authentication in that successful authentication requires both sides of the connection to have knowledge of the user's password. If the client side lacks the user's password or the server side lacks the proper verification key, the authentication will fail. 


References

*	[http://srp.stanford.edu/](http://srp.stanford.edu/)
*	[http://srp.stanford.edu/demo/demo.html](http://srp.stanford.edu/demo/demo.html)

Usage example
=============


	username = "user"
	password = "password"

	require 'srp'
	prime_length = 1024


	# The salt and verifier should be stored on the server database.

		@auth = SRP::Verifier.new(prime_length).generate_userauth(username, password)
		# @auth is a hash containing :username, :verifier and :salt


	# ~~~ Begin Authentication ~~~

		client = SRP::Client.new(prime_length)
		A = client.start_authentication()


	# Client => Server: username, A

		# Server retrieves user's verifier and salt from the database.
		v = @auth[:verifier]
		salt = @auth[:salt]

		# Server generates challenge for the client.
		verifier = SRP::Verifier.new(prime_length)
		session = srp.get_challenge_and_proof(username, v, salt, A)

		# Server sends the challenge containing salt and B to client.
		response = session[:challenge]

		# Server has to persist proof to authenticate the client response.
		@proof = session[:proof]


	# Server => Client: salt, B

		# Client calculates M as a response to the challenge.
		client_M = client.process_challenge(username, password, salt, B)


	# Client => Server: username, M

		# New verifier may be instantiated on the server.
		verifier = SRP::Verifier.new(prime_length)

		# Verify challenge response M.
		# The Verifier state is passed in @proof.
		server_H_AMK = verifier.verify_session(@proof, client_M)
		# Is false if authentication failed.


		# At this point, the client and server should have a common session key
		# that is secure (i.e. not known to an outside party).  To finish
		# authentication, they must prove to each other that their keys are
		# identical.


	# Server => Client: H(AMK)

		client.verify(server_H_AMK) == true


