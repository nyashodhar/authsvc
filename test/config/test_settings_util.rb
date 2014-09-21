#######################################################
#
# Utility class that provides values for some settings
# used in integration tests
#
#######################################################

class TestSettingsUtil

  def initialize
    config_file = "#{Rails.root}/test/config/test_settings.yml"
    test_settings_yaml = YAML::load_file(config_file)
    the_environment = Rails.env.to_str
    @test_settings_for_env = test_settings_yaml[the_environment]
  end

  def get_target_service_url
    return @test_settings_for_env['target_service_url']
  end
end