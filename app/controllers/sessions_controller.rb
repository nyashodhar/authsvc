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
  skip_before_action :verify_authenticity_token, :only => [:login, :logout]

  prepend_before_filter :require_no_authentication, :only => [:login]
  include Devise::Controllers::Helpers

  respond_to :json

  #
  # Note: Check if there is a sign-in for the auth token, and that the sign-in
  # is not expired
  #
  before_action :ensureLoggedInAndAuthTokenNotExpired, :only => [:verify, :logout]

  ################
  # Verify token
  # GET /user/token/verify
  # EXAMPLE LOCAL:
  #   curl -v -X GET http://127.0.0.1:3000/user/auth -H "X-User-Token: GcZy__QhxcxFvdqgpTtz"
  # EXAMPLE CI: 
  #   curl -v -X GET https://authpetpalci.herokuapp.com/user/auth -H "X-User-Token: KVNJ9J2DSZ9boGcz4HNi"
  ################
  def verify
    user = getUserByAuthToken(request)
    theResponse = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token}
    render :status => 200, :json => theResponse
  end

  #
  # Note: Before a sign-in, we need to check if the current token is expired
  # If it's expired, we need to make sure it's reset. Otherwise the user will
  # be allowed to continue to use the auth token even after it has expired!
  #
  before_action :clearStaleTokenBeforeSignIn, :only => [:login]

  ################
  # Sign in:
  # POST /user/auth
  # EXAMPLE LOCAL:
  #   curl -v -X POST http://127.0.0.1:3000/user/auth -H "Content-Type: application/json" -H "Accept: application/json" -d '{"user":{"email":"test4@example.com", "password":"Test1234"}}'
  # EXAMPLE CI:
  #   curl -v -X POST https://authpetpalci.herokuapp.com/user/auth -H "Content-Type: application/json" -H "Accept: application/json" -d '{"user":{"email":"herrstrudel@gmail.com", "password":"Test1234"}}'
  ################
  def login

    signInParams = sign_in_params
    password = signInParams[:password]

    if(password.blank?)
      logger.error "No password specified, can't process login.\n"
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

    theResponse = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token}
    render :status => 200, :json => theResponse
    return
  end

  ################
  # Sign out:
  #
  # DELETE /user/auth
  # curl -v -X DELETE http://127.0.0.1:3000/user/auth -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json"
  ################
  def logout
    user = getUserByAuthToken(request)
    clearAuthTokenForUser(user)
    head :no_content
  end

end