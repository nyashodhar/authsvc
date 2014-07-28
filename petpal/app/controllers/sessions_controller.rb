
########################################################
#
# This class provides authentication services
#
# Example of operations performed are:
#
# - Sign in - to obtain token
# - Sign out
# - Verify token
#
########################################################
class SessionsController < Devise::SessionsController

  include ApplicationHelper

  # Required to for devise to not require the presence of an authenticity token
  skip_before_action :verify_authenticity_token, :only => [:create, :destroy]

  prepend_before_filter :require_no_authentication, :only => [:create]
  include Devise::Controllers::Helpers

  respond_to :json

  ################
  # Verify token
  # GET /user/token/verify
  # curl -X GET http://127.0.0.1:3000/user/token/verify -H "X-User-Token: eXcPsqL-19yzxVpYceeF"
  ################
  def verify

    STDOUT.write "SessionsController#verify: HELLO THERE\n"
    STDOUT.write "current_user = #{current_user.inspect}\n"
    STDOUT.write "session[:userId] = #{session[:userId]}\n"
    STDOUT.write "session = #{session.inspect}\n"

    token = request.headers['X-User-Token']

    # Note: This method is in ApplicationHelper
    userInfo = getLoggedInUser(request)

    # Note: This method is in ApplicationHelper
    renderAuthResponse(userInfo)

    #if(userInfo.blank?)
    #  render :status => 403, :json => I18n.t("token_verification_failed")
    #else
    #  # TODO: Refresh the expiration time of the token
    #  render :status => 200, :json => userInfo[0]
    #end
  end

  ################
  # Sign in:
  # POST /user/login
  # curl -X POST http://127.0.0.1:3000/user/login.json -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234"}}'
  ################

  #
  # Note: Before a sign-in, we need to check if the current token is expired
  # If it's expired, we need to make sure it's reset. Otherwise the user will
  # be allowed to continue to use the auth token even after it has expired!
  #

  before_action :clearStaleTokenBeforeSignIn, :only => [:create]

  def create
    super
  end

  ################
  # Sign out:
  # DELETE /user/logout
  # curl -X DELETE http://127.0.0.1:3000/user/logout.json -H "X-User-Email: test@example.com" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json"
  ################
  def destroy
    super
  end

end