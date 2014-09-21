
class LocalIntegrationTest < BaseIntegrationTest

  def create_headers(http_method)
    if(http_method.eql?("POST") || http_method.eql?("PUT"))
      return { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json' }
    end
    if(http_method.eql?("GET"))
      return {'Content-Type' => 'application/json', 'Accept' => 'application/json' }
    end
  end

  def create_headers_with_auth_token(http_method, auth_token)
    if(http_method.eql?("POST") || http_method.eql?("PUT"))
      return { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json', 'X-User-Token' => auth_token }
    end

    if(http_method.eql?("GET"))
      return {'Content-Type' => 'application/json', 'Accept' => 'application/json', 'X-User-Token' => auth_token }
    end
  end

  def do_get_with_headers(api_uri, my_headers)
    get api_uri, nil, my_headers
    return response
  end

  def do_post_with_headers(api_uri, my_body, my_headers)
    post api_uri, my_body, my_headers
    return response
  end

  def do_put_with_headers(api_uri, my_body, my_headers)
    put api_uri, my_body, my_headers
    return response
  end

  def assert_response_code(response, expected_response_code)
    assert_response expected_response_code
  end

  def get_content_type(response)
    return response.headers["Content-Type"]
  end

  #########################################
  # Create a hash containing the headers
  # to be used in a POST request
  #########################################
  def create_post_headers_with_auth_token(auth_token)
    validate_auth_token(auth_token)
    return { 'CONTENT_TYPE' => 'application/json', 'ACCEPT' => 'application/json', 'X-User-Token' => auth_token}
  end

  #########################################
  # Create a hash containing the headers
  # to be used in a GET request
  #########################################
  def create_get_headers_with_auth_token(auth_token)
    validate_auth_token(auth_token)
    return {'Content-Type' => 'application/json', 'Accept' => 'application/json', 'X-User-Token' => auth_token}
  end

  private

  def validate_auth_token(auth_token)
    if(auth_token.blank?)
      raise 'Parameter auth_token not specified'
    end

    if(auth_token.eql?('GOOD') && auth_token.eql?('BAD'))
      raise 'Invalid value #{auth_token} for auth_token. Value must be either \'GOOD\' or \'BAD\''
    end
  end

end