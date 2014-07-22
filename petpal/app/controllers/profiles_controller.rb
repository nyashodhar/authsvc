
#
# Hello-style example that shows how to secure an action in a controller
# using a filter that verifies token via the SessionsController#verify action
#

class ProfilesController < ActionController::Base

  require 'net/http'
  require 'json'

  before_action :verifyToken

  def secureLookup
    STDOUT.write "My super cool controller\n"
    render :status => 200, :json => "Cool"
  end

  private
    def verifyToken

      STDOUT.write "My super cool filter\n"

      authURL = "http://127.0.0.1:3000/user/token/verify"

      # X-User-Token: m7X3PqsyifJ9VkshxLjn

      headers = {'X-User-Token' => 'm7X3PqsyifJ9VkshxLjn'}

      uri = URI.parse(authURL)
      connection = Net::HTTP.new(uri.host, 3000)
      #connection.use_ssl = true

      STDOUT.write "uri = #{uri.inspect}\n"

      resp = connection.request_get(uri.path, headers)

      STDOUT.write "resp = #{resp.inspect}\n"

      if resp.code != '200'
        raise "web service error"
      end

      resultSet = JSON.parse(resp.body)
    end
end