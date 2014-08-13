require 'test_helper'

class LoginFlowsTest < ActionDispatch::IntegrationTest

  #
  # Verify that a bunch of devise MVC HTML controllers are disabled and give 404 page
  #
  test "Devise controllers are disabled in routes" do

    my_request_headers = {'Content-Type' => 'application/json'}
    get "users/sign_in", nil, my_request_headers
    assert_response :not_found
    assert(response.headers["Content-Type"].downcase.include?("text/html"))

    my_request_headers = {'Content-Type' => 'application/json'}
    get "users/sign_up", nil, my_request_headers
    assert_response :not_found
    assert(response.headers["Content-Type"].downcase.include?("text/html"))

    my_request_headers = {'Content-Type' => 'application/json'}
    get "users/password/new", nil, my_request_headers
    assert_response :not_found
    assert(response.headers["Content-Type"].downcase.include?("text/html"))

    # This one we are actually using now that password reset is introduced.
    #my_request_headers = {'Content-Type' => 'application/json'}
    #get "users/password/edit", nil, my_request_headers
    #assert_response :not_found
    #assert(response.headers["Content-Type"].downcase.include?("text/html"))

    my_request_headers = {'Content-Type' => 'application/json'}
    get "users/unlock", nil, my_request_headers
    assert_response :not_found
    assert(response.headers["Content-Type"].downcase.include?("text/html"))

    my_request_headers = {'Content-Type' => 'application/json'}
    get "users/unlock/new", nil, my_request_headers
    assert_response :not_found
    assert(response.headers["Content-Type"].downcase.include?("text/html"))
  end

  #
  # Trigger a password reset
  # Omit email - get 422
  # Use bogus email
  #   - get 201 and no token
  #   - Verify fields in db
  # User real email - get 201 with token
  #   - get 201 and token
  #   - Verify fields in db
  #
  test "Test password reset trigger API" do

    reset_request = '{}'
    reset_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }

    # Omit email - get 422
    post "user/password/reset", reset_request, reset_headers
    assert_response :unprocessable_entity

    # Bogus email - get 201
    reset_request = '{"email":"whatever@petpal.com"}'
    post "user/password/reset", reset_request, reset_headers
    assert_response :created
    reset_response = JSON.parse(response.body)
    assert_not_nil(reset_response["email"])
    assert_not_nil(reset_response["reset_password_sent_at"])
    assert_nil(reset_response["reset_password_token"])

    # Valid email - get 201 response and token

    user = User.find_by_email("user1@petpal.com")
    assert(user.reset_password_token.blank?)
    assert(user.reset_password_sent_at.blank?)

    reset_request = '{"email":"user1@petpal.com"}'
    post "user/password/reset", reset_request, reset_headers
    assert_response :created
    reset_response = JSON.parse(response.body)
    assert_not_nil(reset_response["email"])
    assert_not_nil(reset_response["reset_password_sent_at"])
    assert_not_nil(reset_response["reset_password_token"])

    user = User.find_by_email("user1@petpal.com")
    assert(!user.reset_password_token.blank?)
    assert(!user.reset_password_sent_at.blank?)
  end


  #
  # Test that the email address can be changed
  # - Do login
  # - Do user edit and update email address to an address not in in use by other user => should be successful
  # - Do logout
  # - Do login using the old email address => You should get a 200 because the new email is not confirmed yet
  # - Visit the email change confirmation link
  # - Do login using the old email address => You should get a 401 now because email has been changed
  # - Do login using the new email address => You should be successful
  #
  test "Test email change and confirmation flow for new email address" do

    login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
    login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }

    # login
    post "user/auth", login_request, login_headers
    assert_response :success

    login_response = JSON.parse(response.body)
    assert_not_nil(login_response["authentication_token"])
    assert_not_nil(login_response["email"])
    assert_not_nil(login_response["id"])

    # edit password -> success
    auth_token = login_response["authentication_token"]
    edit_request_data = '{"user":{"email":"testpetpaluser1@petpal.com", "password":"Test1234", "current_password":"Test1234"}}'
    edit_request_headers = {'Content-Type' => 'application/json', 'ACCEPT' => 'application/json', 'X-User-Token' => auth_token}
    put "user", edit_request_data, edit_request_headers

    assert_response :success
    assert_not_nil(JSON.parse(response.body)["authentication_token"])
    assert_not_nil(JSON.parse(response.body)["email"])
    assert_not_nil(JSON.parse(response.body)["id"])
    assert_not_nil(JSON.parse(response.body)["confirmation_token"])

    confirmation_token = JSON.parse(response.body)["confirmation_token"]

    user = User.find_by_id(1)
    assert(user.unconfirmed_email.eql?('testpetpaluser1@petpal.com'))
    assert(user.confirmed_at.blank?)
    assert(!user.confirmation_sent_at.blank?)
    assert(!user.confirmation_token.blank?)

    # logout user
    #new_auth_token = JSON.parse(response.body)["authentication_token"]
    #logout_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => new_auth_token}
    #delete "user/auth", nil, logout_request_headers
    #assert_response :success
    #assert(response.body.blank?)

    #sleep(1)

    # login with old email - should still get 200 since email confirmation not complete
    post "user/auth", login_request, login_headers
    assert_response :success

    #
    # Visit the email confirmation link - this will update the email address in the user
    # and clear the unconfirmed_email field as well...
    #
    my_request_headers = {'Content-Type' => 'text/html'}
    my_url_params = {"confirmation_token" => confirmation_token}
    get "users/confirmation", my_url_params, my_request_headers
    assert_response :created

    user = User.find_by_id(1)
    assert(user.unconfirmed_email.blank?)
    assert(!user.confirmed_at.blank?)
    assert(!user.confirmation_sent_at.blank?)
    assert(user.confirmation_token.blank?)

    # login with old email - should now get a 401 since the email confirmation is now complete
    post "user/auth", login_request, login_headers
    assert_response :unauthorized

    # login with new email - should succeed now that email confirmation is completed
    new_login_request = '{"user":{"email":"testpetpaluser1@petpal.com", "password":"Test1234"}}'
    new_login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
    post "user/auth", new_login_request, new_login_headers
    assert_response :success
    assert_not_nil(JSON.parse(response.body)["authentication_token"])
    assert_not_nil(JSON.parse(response.body)["email"])
    assert_not_nil(JSON.parse(response.body)["id"])

    #
    # Visit the confirmation link a 2nd time, we should no longer get the 201
    # response that indicates success, but rather get some 404 response
    #
    get "users/confirmation", my_url_params, my_request_headers
    assert_response :not_found

    user = User.find_by_id(1)
    assert(user.unconfirmed_email.blank?)
    assert(!user.confirmed_at.blank?)
    assert(!user.confirmation_sent_at.blank?)
    assert(user.confirmation_token.blank?)
  end

  #
  # Test that requests for which the URL path could not be mapped to any
  # controller get a proper 404 formatted response
  #
  test "Verify 404 response for URL with no mapping - JSON and HTML" do

    # Do request as JSON client

    my_request_headers = {'Content-Type' => 'application/json', 'Accept' => 'application/json'}
    get "user/authfoobar", nil, my_request_headers
    assert_response :not_found

    my_response = JSON.parse(response.body)
    assert_not_nil(my_response["error"])
    assert(my_response["error"].eql?("Resource not found"))

    # Do request as HTML client

    my_request_headers = {'Content-Type' => 'application/json'}
    get "user/authfoobar", nil, my_request_headers
    assert_response :not_found
    assert(response.headers["Content-Type"].downcase.include?("text/html"))
  end

  #
  # Test that requests with invalid json are handled properly
  # Send a request with invalid JSON, you should get a 400 JSON response
  #
  test "Verify invalid JSON handling" do
    invalid_json = '{"user"=#rty$$["email":"user1@petpal.com", "password":"Test1234"}}'
    headers = { 'CONTENT_TYPE' => 'application/json' }
    post "user/auth", invalid_json, headers
    assert_response :bad_request

    the_response = JSON.parse(response.body)
    assert_not_nil(the_response["error"])
    assert(the_response["error"].eql?("There was a problem in your JSON"))
  end


  #
  # For a user not logged in:
  # - Try to trigger sending of confirmation instruction - Should give 401 since not logged in
  # - Log in
  # - Trigger resending of email confirmation instruction
  #    - Verify that the confirmation gets updated
  # - Verify the email by visiting link
  # - Verify that trying to retrigger the sending of the confirmation again fails because the
  #    use has alread verified the email
  #
  test "Test API to trigger email confirmation" do

    # Try to trigger email to be sent, should give 401 since it's a protected API call

    trigger_email_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => "bogus123"}
    post "user/email/confirmation", nil, trigger_email_request_headers
    assert_response :unauthorized

    # Do a login

    login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
    login_request_headers = { 'CONTENT_TYPE' => 'application/json' }
    post "user/auth", login_request, login_request_headers
    assert_response :success

    login_response = JSON.parse(response.body)
    assert_not_nil(login_response["authentication_token"])
    assert_not_nil(login_response["email"])
    assert_not_nil(login_response["id"])
    auth_token = login_response["authentication_token"]
    user_id = login_response["id"]

    user = User.find_by_id(user_id)
    old_confirmation_token = user.confirmation_token

    # Trigger sending of email confirmation to be sent, should succeed

    trigger_email_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => auth_token}
    post "user/email/confirmation", nil, trigger_email_request_headers
    assert_response :created
    trigger_response = JSON.parse(response.body)
    assert_not_nil(trigger_response["confirmation_sent_at"])
    assert_not_nil(trigger_response["confirmation_token"])

    raw_token = trigger_response["confirmation_token"]

    # The confirmation token should have been updated at this point..

    user = User.find_by_id(user_id)
    assert(user.email.eql?('user1@petpal.com'))
    assert(user.confirmed_at.blank?)
    assert(!user.confirmation_token.blank?)
    assert(!user.confirmation_sent_at.blank?)
    assert(!user.confirmation_token.eql?(old_confirmation_token))
    assert(user.unconfirmed_email.blank?)

    #
    # Visit the email confirmation link
    # - confirmed_at should be set
    # - confirmation_token will be cleared
    #

    my_request_headers = {'Content-Type' => 'text/html'}
    my_url_params = {"confirmation_token" => raw_token}
    get "users/confirmation", my_url_params, my_request_headers
    assert_response :created

    user = User.find_by_id(user_id)
    assert(!user.confirmed_at.blank?)
    assert(user.confirmation_token.blank?)
    assert(!user.confirmation_sent_at.blank?)
    assert(user.unconfirmed_email.blank?)

    #
    # Try to trigger the sending of the confirmation instructions again, it should fail with a 412 since
    # user's email is already confirmed.
    #

    trigger_email_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => auth_token}
    post "user/email/confirmation", nil, trigger_email_request_headers
    assert_response :precondition_failed
  end


  #
  # Test to login user
  # and then verify the user auth token
  #
  test "login and verify token" do
    # login via http
    login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
    #login_request_headers = '{"Content-Type" : "application/json"}'
    headers = { 'CONTENT_TYPE' => 'application/json' }
    post "user/auth", login_request, headers
    assert_response :success
	
	  login_response = JSON.parse(response.body)
    assert_not_nil(login_response["authentication_token"])
    assert_not_nil(login_response["email"])
    assert_not_nil(login_response["id"])

    auth_token = login_response["authentication_token"]
    verify_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => auth_token}
    get "user/auth", nil, verify_request_headers
    assert_response :success

    verify_response = JSON.parse(response.body)
    assert_not_nil(verify_response["authentication_token"])
    assert_not_nil(verify_response["email"])
    assert_not_nil(verify_response["id"])
  end

	#
	# Test logout
	# - Do login
	# - Use verify API and check you get a 200
	# - Do logout
	# - Use verify API and check you get a 401
	#
  test "token expiry with logout" do
    # login via http
    login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
    #login_request_headers = '{"Content-Type" : "application/json"}'
    headers = { 'CONTENT_TYPE' => 'application/json' }
    post "user/auth", login_request, headers
    assert_response :success
	
	  login_response = JSON.parse(response.body)
    assert_not_nil(login_response["authentication_token"])
    assert_not_nil(login_response["email"])
    assert_not_nil(login_response["id"])

    auth_token = login_response["authentication_token"]
    verify_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => auth_token}
    delete "user/auth", nil, verify_request_headers
    assert_response :success
	  assert(response.body.blank?)
    
    get "user/auth", nil, verify_request_headers
    assert_response :unauthorized
  end

  #
	# Test token expiration for verify
	# - Do login
	# - Use verify API and check you get a 200
	# - Sleep until the token is expired
	# - Use verify API and check you get a 401 
	#
  test "token expiry without logout" do
    # login via http
    login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
    #login_request_headers = '{"Content-Type" : "application/json"}'
    headers = { 'CONTENT_TYPE' => 'application/json' }
    post "user/auth", login_request, headers
    assert_response :success
	
	  login_response = JSON.parse(response.body)
    assert_not_nil(login_response["authentication_token"])
    assert_not_nil(login_response["email"])
    assert_not_nil(login_response["id"])

    # verify
    auth_token = login_response["authentication_token"]
    verify_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => auth_token}
    get "user/auth", nil, verify_request_headers
    assert_response :success
    verify_response = JSON.parse(response.body)
    assert_not_nil(verify_response["authentication_token"])
    assert_not_nil(verify_response["email"])
    assert_not_nil(verify_response["id"])
    
    sleep(3)

    get "user/auth", nil, verify_request_headers
    assert_response :unauthorized
  end

  #
  # Test stale token reset
  # - Do login
  # - Use verify API and check you get a 200
  # - Sleep until token is expired
  # - Do a sign-in and verify that you get a new token
  #
  test "token refresh on relogin" do
    
    login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
    # TODO: ACCEPT header should not be included usually as this should be plain JSON API
    login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
    
    # login
    post "user/auth", login_request, login_headers
    assert_response :success
	
	  login_response = JSON.parse(response.body)
    assert_not_nil(login_response["authentication_token"])
    assert_not_nil(login_response["email"])
    assert_not_nil(login_response["id"])

    # verify
    auth_token = login_response["authentication_token"]
    verify_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => auth_token}
    get "user/auth", nil, verify_request_headers
    assert_response :success
    verify_response = JSON.parse(response.body)
    assert_not_nil(verify_response["authentication_token"])
    assert_not_nil(verify_response["email"])
    assert_not_nil(verify_response["id"])
    
    sleep(3)

    post "user/auth", login_request, login_headers
    assert_response :success
	
	  new_login_response = JSON.parse(response.body)
	  assert_not_equal(auth_token, new_login_response["authentication_token"], "Auth Tokens are same")

  end


  #
  # Test email address can't be updated to address in use by other user
  # - Do login
  # - Do user edit and update email address to an address in use by other user, you 422
  #
	test "edit email to already in use email" do
	    
	  login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
	  # TODO: ACCEPT header should not be included usually as this should be plain JSON API
	  login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
	    
	  # login
	  post "user/auth", login_request, login_headers
	  assert_response :success
		
		login_response = JSON.parse(response.body)
	  assert_not_nil(login_response["authentication_token"])
	  assert_not_nil(login_response["email"])
	  assert_not_nil(login_response["id"])

	  #edit email address
	  auth_token = login_response["authentication_token"]
	  edit_request_data = '{"user":{"email":"user2@petpal.com", "password":"Test1234", "current_password":"Test1234"}}'
	  edit_request_headers = {'Content-Type' => 'application/json', 'ACCEPT' => 'application/json', 'X-User-Token' => auth_token}
	  put "user", edit_request_data, edit_request_headers

	  assert_response(422)
	end

  #
  # Test that password can be updated when current_password is supplied correctly
  # - Do login
  # - Do edit user and specify the correct password in "current_password" => you should be successful
  # - Do logout
  # - Try to log in with the old password => You should get a 401
  # - Try to log in with the new password => You should be successful
  #
	test "edit password and verify the edit" do
	    
	  login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
	  login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
	    
	  # login
	  post "user/auth", login_request, login_headers
	  assert_response :success
		
		login_response = JSON.parse(response.body)
	  assert_not_nil(login_response["authentication_token"])
	  assert_not_nil(login_response["email"])
	  assert_not_nil(login_response["id"])

	  # edit password -> success
	  auth_token = login_response["authentication_token"]
	  edit_request_data = '{"user":{"email":"user1@petpal.com", "password":"secret11", "current_password":"Test1234"}}'
	  edit_request_headers = {'Content-Type' => 'application/json', 'ACCEPT' => 'application/json', 'X-User-Token' => auth_token}
	  put "user", edit_request_data, edit_request_headers

	  assert_response :success
	  assert_not_nil(JSON.parse(response.body)["authentication_token"])
	  assert_not_nil(JSON.parse(response.body)["email"])
	  assert_not_nil(JSON.parse(response.body)["id"])

	  # logout user
	  new_auth_token = JSON.parse(response.body)["authentication_token"]
	  logout_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => new_auth_token}
	  delete "user/auth", nil, logout_request_headers
	  assert_response :success
		assert(response.body.blank?)

		sleep(1)

		# login with old password
		post "user/auth", login_request, login_headers
	  assert_response :unauthorized
	    
	  # login
	  new_login_request = '{"user":{"email":"user1@petpal.com", "password":"secret11"}}'
	  new_login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
	  post "user/auth", new_login_request, new_login_headers
	  assert_response :success
	  assert_not_nil(JSON.parse(response.body)["authentication_token"])
	  assert_not_nil(JSON.parse(response.body)["email"])
	  assert_not_nil(JSON.parse(response.body)["id"])

	end

  #
  # Test creating a user whose email is already taken
  # - You should get a 422 with this JSON: {"email":["has already been taken"]}
  #
	test "create user with existing email" do
	    
	  register_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
	  register_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }

	  # register
	  post "user", register_request, register_headers
	  assert_response(422)
	end

  #
  # Test creating a user whose email is not already taken
  # - The creation should be successful and a confirmation token should be present.
  # - After user creation login should be successful even though user is not confirmed yet
  # - After confirmation the 'confirmed_at' time should be written
  # - It should not be possible to use the confirmation token more than one time
  #
	test "Create user success and email confirmation" do
	    
	  register_request = '{"user":{"email":"testuser1@petpal.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
	  register_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }

	  # register
	  post "user", register_request, register_headers
	  assert_response :success
	  assert_not_nil(JSON.parse(response.body)["email"])
	  assert_not_nil(JSON.parse(response.body)["id"])
    assert_not_nil(JSON.parse(response.body)["confirmation_token"])

    confirmation_token = JSON.parse(response.body)["confirmation_token"]
    user_id = JSON.parse(response.body)["id"]

    user = User.find_by_id(user_id)
    assert(user.email.eql?('testuser1@petpal.com'))
    assert(user.confirmed_at.blank?)
    assert(!user.confirmation_token.blank?)
    assert(!user.confirmation_sent_at.blank?)

    # Do a login, it should be successful even though email is not confirmed yet

    login_request = '{"user":{"email":"testuser1@petpal.com", "password":"Test1234"}}'
    login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
    post "user/auth", login_request, login_headers
    assert_response :success

    #
    # Visit the email confirmation link
    # - confirmed_at should be set
    # - confirmation_token will be cleared
    #
    my_request_headers = {'Content-Type' => 'text/html'}
    my_url_params = {"confirmation_token" => confirmation_token}
    get "users/confirmation", my_url_params, my_request_headers
    assert_response :created

    user = User.find_by_id(user_id)
    assert(user.email.eql?('testuser1@petpal.com'))
    assert(!user.confirmed_at.blank?)
    assert(user.confirmation_token.blank?)
    assert(!user.confirmation_sent_at.blank?)

    #
    # Visit the confirmation link a 2nd time, we should no longer get the 201
    # response that indicates success, but rather get some 404 response
    #
    get "users/confirmation", my_url_params, my_request_headers
    assert_response :not_found

    # Check that user is still as expected after bogus 2nd confirmation attempt

    user = User.find_by_id(user_id)
    assert(user.email.eql?('testuser1@petpal.com'))
    assert(!user.confirmed_at.blank?)
    assert(user.confirmation_token.blank?)
    assert(!user.confirmation_sent_at.blank?)

  end

  #
  # Test that deleted users can't login
  # - Delete an existing user
  # - Try to login with the user/password of the deleted user => you should get a 401
  #
	test "delete user and verify login failure" do
	  login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
	  login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
	    
	  # login
	  post "user/auth", login_request, login_headers
	  assert_response :success

	  # logout user
	  new_auth_token = JSON.parse(response.body)["authentication_token"]
	  delete_request_headers = {'Content-Type' => 'application/json', 'ACCEPT' => 'application/json', 'X-User-Token' => new_auth_token}

		# delete user
		delete "user", nil, delete_request_headers
	  assert_response :success

	  # try login again
	  post "user/auth", login_request, login_headers
	  assert_response :unauthorized
	end

  #
  # Test creating a user whose email is taken by a previously deleted user
  # - Delete an existing user
  # - Try to create a new user with the same email as the previously deleted user
  #     You should get a 422 with this JSON: {"email":["has already been taken"]}
  #
	test "create user with deleted user email" do
	  login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
	  login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
	    
	  # login
	  post "user/auth", login_request, login_headers
	  assert_response :success

    # logout user
 	  new_auth_token = JSON.parse(response.body)["authentication_token"]
	  delete_request_headers = {'Content-Type' => 'application/json', 'ACCEPT' => 'application/json', 'X-User-Token' => new_auth_token}

		# delete user
		delete "user", nil, delete_request_headers
	  assert_response :success

	  register_request = '{"user":{"email":"user1@petpal.com", "password":"Test123456", "password_confirmation":"Test123456"}}'
	  register_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
	    
	  # register with deleted user email
	  post "user", register_request, register_headers
	  assert_response(422)
	end

  #
  # Verify the 'find' API call in the registrations controller
  # - Do login
  # - Do GET /user => you should be successful
  #
	test "login and then get user" do
	  # login via http
	  login_request = '{"user":{"email":"user1@petpal.com", "password":"Test1234"}}'
	  #login_request_headers = '{"Content-Type" : "application/json"}'
	  headers = { 'CONTENT_TYPE' => 'application/json' }
	  post "user/auth", login_request, headers
	  assert_response :success
		
		login_response = JSON.parse(response.body)
	  assert_not_nil(login_response["authentication_token"])
	  assert_not_nil(login_response["email"])
	  assert_not_nil(login_response["id"])

	  # get user
	  auth_token = login_response["authentication_token"]
	  find_request_headers = {'Content-Type' => 'application/json', 'ACCEPT' => 'application/json', 'X-User-Token' => auth_token}

		# delete user
		get "user", nil, find_request_headers
	  assert_response :success
		
		get_response = JSON.parse(response.body)
	  assert_not_nil(get_response["authentication_token"])
	  assert_not_nil(get_response["email"])
	  assert_not_nil(get_response["id"])
	end

  #
  # Check that login with missing password gets 422
  # - In the request, include the email but omit the password field => You should get a 422
  #
	test "login fail with missing password" do
	  # login via http
	  login_request = '{"user":{"email":"user1@petpal.com"}}'
	  #login_request_headers = '{"Content-Type" : "application/json"}'
	  headers = { 'CONTENT_TYPE' => 'application/json' }
	  post "user/auth", login_request, headers
	  assert_response(422)
	end

  #
  # Check that login request with a missing email address gets a 422
  #
	test "login fail with missing email" do
	  # login via http
	  login_request = '{"user":{"password":"Test1234"}}'
	  #login_request_headers = '{"Content-Type" : "application/json"}'
	  headers = { 'CONTENT_TYPE' => 'application/json' }
	  post "user/auth", login_request, headers
	  assert_response(422)
	end

  #
  # Check that login for non-existing user does not work
  # - Do login using bogus email/password => You should get a 401
  #
	test "login fail with invalid credentials" do
	  # login via http
	  login_request = '{"user":{"email":"test1@petpal.com", "password":"secret11"}}'
	  #login_request_headers = '{"Content-Type" : "application/json"}'
	  headers = { 'CONTENT_TYPE' => 'application/json' }
	  post "user/auth", login_request, headers
	  assert_response(401)
	end
end
