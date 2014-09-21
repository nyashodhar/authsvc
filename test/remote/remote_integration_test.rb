
class RemoteIntegrationTest < BaseIntegrationTest

  setup do
    @target_svc_base_url = @@test_settings_util.get_target_service_url
  end

  ###############################################
  #
  # When we are running a test against a remote
  # service, we don't have test fixture containing
  # valid list of emails. This method is used to
  # create a new user to be used in test-cases
  #
  ###############################################
  def obtain_user_email

    time = Time.new
    email_to_create = "integrationtest-#{time.year}#{time.month}#{time.day}-#{time.hour}#{time.min}-#{time.usec}@petpal.com"
    password = "Test1234"

    registration_request_user = { "email" => email_to_create, "password" => password, "password_confirmation" => password }
    registration_request = { "user" => registration_request_user}
    registration_request_headers = create_headers("POST")

    response = do_post_with_headers("user", registration_request.to_json, registration_request_headers)
    assert_response_code(response, 200)

    # create the user
    the_response_hash = JSON.parse(response.body)
    assert_not_nil(the_response_hash["email"])
    assert(the_response_hash["email"].eql?(email_to_create))
    assert_not_nil(the_response_hash["id"])

    return email_to_create
  end

  def create_headers(http_method)
    return {'Content-Type' => 'application/json', 'Accept' => 'application/json' }
  end

  def create_headers_with_auth_token(http_method, auth_token)
    return {'Content-Type' => 'application/json', 'Accept' => 'application/json', 'X-User-Token' => auth_token }
  end

  def get_content_type(response)
    return response.headers[:content_type]
  end

  def do_get_with_headers(api_uri, my_headers)
    begin
      return RestClient.get("#{@target_svc_base_url}/#{api_uri}", my_headers)
    rescue => e
      if(defined? e.response)
        return e.response
      else
        raise "do_get_with_headers_remote(): Unexpected error! No response for url = #{@target_svc_base_url}/#{api_uri}, headers = my_headers, error = #{e}"
      end
    end
  end

  def do_put_with_headers(api_uri, my_body, my_headers)
    begin
      return RestClient.put("#{@target_svc_base_url}/#{api_uri}", my_body, my_headers)
    rescue => e
      if(defined? e.response)
        return e.response
      else
        raise "do_put_with_headers_remote(): Unexpected error! No response for url = #{@target_svc_base_url}/#{api_uri}, body = #{my_body}, headers = my_headers, error = #{e}"
      end
    end
  end

  def do_post_with_headers(api_uri, my_body, my_headers)
    begin
      return RestClient.post("#{@target_svc_base_url}/#{api_uri}", my_body, my_headers)
    rescue => e
      if(defined? e.response)
        return e.response
      else
        raise "do_post_with_headers_remote(): Unexpected error! No response for url = #{@target_svc_base_url}/#{api_uri}, body = #{my_body}, headers = my_headers, error = #{e}"
      end
    end
  end

  def assert_response_code(response, expected_response_code)
    if(response == nil)
      raise "Can't assert response code in response, response is blank: #{response}\n"
    end
    if(!response.code.to_s.eql?(expected_response_code.to_s))
      raise "Unexpected response code. Expected response code: #{expected_response_code}, actual response code: #{response.code}\n"
    end
  end

end