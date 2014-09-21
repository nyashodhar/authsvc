module RegistrationsControllerTests

  def check_password_reset_api

    reset_request = {}
    reset_headers = create_headers("POST")

    # Omit email - get 422
    response = do_post_with_headers("user/password/reset", reset_request.to_json, reset_headers)
    assert_response_code(response, 422)

    # Bogus email - get 201
    reset_request = { "email" => "whatever@petpal.com" }
    response = do_post_with_headers("user/password/reset", reset_request.to_json, reset_headers)
    assert_response_code(response, 201)
    reset_response = JSON.parse(response.body)
    assert_not_nil(reset_response["email"])
    assert_not_nil(reset_response["reset_password_sent_at"])
    assert_nil(reset_response["reset_password_token"])

    #
    # Valid email - get 201 response and token
    #

    email = obtain_user_email

    if(@local_test)
      user = User.find_by_email(email)
      assert(user.reset_password_token.blank?)
      assert(user.reset_password_sent_at.blank?)
    end

    reset_request = { "email" => email }
    response = do_post_with_headers("user/password/reset", reset_request.to_json, reset_headers)
    assert_response_code(response, 201)
    reset_response = JSON.parse(response.body)
    assert_not_nil(reset_response["email"])
    assert_not_nil(reset_response["reset_password_sent_at"])

    if(@local_test)

      #
      # Note: Only when running locally will the service under
      # test have the special config to include the password
      # reset token in the response for testing purposes.
      #

      assert_not_nil(reset_response["reset_password_token"])

      user = User.find_by_email("user1@petpal.com")
      assert(!user.reset_password_token.blank?)
      assert(!user.reset_password_sent_at.blank?)
    end
  end

end