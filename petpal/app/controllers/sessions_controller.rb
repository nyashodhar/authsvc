
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

  #
  # Note: Check if there is a sign-in for the auth token, and that the sign-in
  # is not expired
  #
  before_action :ensureLoggedInAndAuthTokenNotExpired, :only => [:verify, :destroy]

  ################
  # Verify token
  # GET /user/token/verify
  # curl -X GET http://127.0.0.1:3000/user/token/verify -H "X-User-Token: GcZy__QhxcxFvdqgpTtz"
  ################
  def verify
    user = getUserByAuthToken(request)
    render :status => 200, :json => user
  end

  #
  # Note: Before a sign-in, we need to check if the current token is expired
  # If it's expired, we need to make sure it's reset. Otherwise the user will
  # be allowed to continue to use the auth token even after it has expired!
  #
  before_action :clearStaleTokenBeforeSignIn, :only => [:create]

  ################
  # Sign in:
  # POST /user/login
  # curl -X POST http://127.0.0.1:3000/user/login -H "Content-Type: application/json" -H "Accept: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234"}}'
  ################
  def create

    #
    # THIS IS A HACK, FIX BY IMPLEMENTING
    #

    if(request.headers[:HTTP_ACCEPT] != "application/json")
      logger.info "Invalid Accept header value #{request.headers[:HTTP_ACCEPT]}, request can't be processed.\n"
      render :status => :unprocessable_entity, :json => I18n.t("422response_invalid_accept_header")
      return
    end
    super
  end

  ################
  # Sign out:
  # DELETE /user/logout
  # curl -X DELETE http://127.0.0.1:3000/user/logout.json -H "X-User-Email: test@example.com" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json"
  ################
  def destroy
    # TODO: Remove .json requirement for end of this URL
    user = getUserByAuthToken(request)
    clearAuthTokenForUser(user)
    super
  end

end