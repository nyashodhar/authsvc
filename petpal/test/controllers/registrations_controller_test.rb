class RegistrationsControllerTest < ActionController::TestCase
  #
  # Test to get Unauthenticated response while trying to access 'lookup'
  # method without sign in.
  #
  test "should get UnAuthenticated" do
  	@request.env["devise.mapping"] = Devise.mappings[:user]
  	@request.headers["X-User-Token"] = "authToken1"
  	response = get :lookup
  	assert_response :forbidden
  	byebug
  	assert((response.body.eql? "Not logged in"), "Not the same stuff")
  end
end