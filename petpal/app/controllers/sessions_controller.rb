
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

    signInParams = sign_in_params
    password = signInParams[:password]

    if(password.blank?)
      logger.info "No password specified, can't process login.\n"
      render :status => :unprocessable_entity, :json => I18n.t("422response_no_password_specified")
      return
    end

    # Note: The filter has already verified the presence in the params at this point, so
    # no need to worry about email being blank here..
    email = signInParams[:email]

    user = User.find_by_email(email)
    if(user.blank?)
      logger.info "No user found for email #{email}\n"
      render :status => 401, :json => I18n.t("401response_invalid_email_or_password")
      return
    end

    passwordCheck = user.valid_password?(password)
    if(!passwordCheck)
      logger.info "Invalid password for user #{email}\n"
      render :status => 401, :json => I18n.t("401response_invalid_email_or_password")
      return
    end

    # Correct email/password has been supplied, update sign-in record
    sign_in(resource_name, user)

    # Give response
    signInResponse = { :id => user.id, :email => email, :authentication_token => user.authentication_token}
    render :status => 200, :json => signInResponse
    return
  end

  ################
  # Sign out:
  # DELETE /user/logout
  # curl -X DELETE http://127.0.0.1:3000/user/logout -H "X-User-Email: test@example.com" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json"
  ################
  def destroy
    user = getUserByAuthToken(request)
    clearAuthTokenForUser(user)
    head :no_content
  end

end