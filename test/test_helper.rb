ENV['RAILS_ENV'] ||= 'test'
require File.expand_path('../../config/environment', __FILE__)
require 'rails/test_help'
require 'rest-client'

require 'config/test_settings_util'
require 'helpers/base_integration_test'
require 'integration/local_integration_test'
require 'remote/remote_integration_test'

require 'controllers/registrations_controller_tests'
require 'helpers/page_not_found_tests'

class ActiveSupport::TestCase
  # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
  fixtures :all

  # Add more helper methods to be used by all tests here...
end
