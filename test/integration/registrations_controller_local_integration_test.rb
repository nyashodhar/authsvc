require 'test_helper'

class RegistrationsControllerLocalIntegrationTest < LocalIntegrationTest

  include RegistrationsControllerTests

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
    check_password_reset_api
  end

end