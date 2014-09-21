module PageNotFoundTests

  def check_devise_pieces_deactivated
    check_page_not_found("users/sign_in")
    check_page_not_found("users/sign_up")
    check_page_not_found("users/password/new")
    check_page_not_found("users/unlock")
    check_page_not_found("users/unlock/new")
  end

  private

  def check_page_not_found(my_uri)
    my_headers = create_headers("GET")
    response = do_get_with_headers(my_uri, my_headers)
    assert_response_code(response, 404)
    content_type = get_content_type(response)
    assert(content_type.downcase.include?("application/json"))
  end

end