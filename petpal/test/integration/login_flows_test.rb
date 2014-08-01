require 'test_helper'

class LoginFlowsTest < ActionDispatch::IntegrationTest

  #
  # Test that requests for which the URL path could not be mapped to any
  # controller get a proper 404 formatted response
  #
  test "Verify invalid 404 for URL with no mapping" do

    my_request_headers = {'Content-Type' => 'application/json'}
    get "user/authfoobar", nil, my_request_headers
    assert_response :not_found

    my_response = JSON.parse(response.body)
    assert_not_nil(my_response["error"])
    assert(my_response["error"].eql?("Resource not found"))
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
# - You should be successful
#
	test "create user success" do
	    
	    register_request = '{"user":{"email":"testuser1@petpal.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
	    register_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
	    
	    # register
	    post "user", register_request, register_headers
	    assert_response :success
	    assert_not_nil(JSON.parse(response.body)["authentication_token"])
	    assert_not_nil(JSON.parse(response.body)["email"])
	    assert_not_nil(JSON.parse(response.body)["id"])
		
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
# Test that the email address can be changed
# - Do login
# - Do user edit and update email address to an address not in in use by other user => should be successful
# - Do logout
# - Do login using the old email address => You should get a 401
# - Do login using the new email address => You should be successful
#
	test "edit email and verify the edit" do
	    
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

	    # logout user
	    new_auth_token = JSON.parse(response.body)["authentication_token"]
	    logout_request_headers = {'Content-Type' => 'application/json', 'X-User-Token' => new_auth_token}
	    delete "user/auth", nil, logout_request_headers
	    assert_response :success
		assert(response.body.blank?)

		sleep(1)

		# login with old email
		post "user/auth", login_request, login_headers
	    assert_response :unauthorized
	    
	    # login with new email
	    new_login_request = '{"user":{"email":"testpetpaluser1@petpal.com", "password":"Test1234"}}'
	    new_login_headers = { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
	    post "user/auth", new_login_request, new_login_headers
	    assert_response :success
	    assert_not_nil(JSON.parse(response.body)["authentication_token"])
	    assert_not_nil(JSON.parse(response.body)["email"])
	    assert_not_nil(JSON.parse(response.body)["id"])

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
