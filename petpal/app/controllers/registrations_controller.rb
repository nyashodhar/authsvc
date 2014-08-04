###################################
#
# This controller implements user CRUD functionality
#
# All actions in this controller are authenticated via token,
# except create operation.
#
###################################

class RegistrationsController < Devise::RegistrationsController

  include ApplicationHelper

  # Required to for devise to not require the presence of an authenticity token
  skip_before_action :verify_authenticity_token, :only => [:create, :editUser, :delete, :triggerConfirmation]

  #
  # Note: Check if there is a sign-in for the auth token, and that the sign-in
  # is not expired
  #
  before_action :ensureLoggedInAndAuthTokenNotExpired, :only => [:find, :editUser, :delete, :triggerConfirmation]

  respond_to :json

  #################
  # Look up user
  # GET /user
  # If the user already was deleted, the user will get a 401
  # curl -v -X GET http://127.0.0.1:3000/user -H "X-User-Token: zZGGxQYUcVxHDXfxVysS"
  #################
  def find
    user = getUserByAuthToken(request)
    theResponse = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token}
    render :status => 200, :json => theResponse
  end

  #######################################################
  # Update user
  # PUT /user
  #
  # If the password is being updated, the request will
  # get a 401 if the current password is not provided
  # correctly
  #
  # EXAMPLE:
  # curl -v -X PUT http://127.0.0.1:3000/user -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json" -d '{"user":{"email":"test4@example.com", "password":"Test1234", "current_password":"Test1234"}}'
  #######################################################
  def editUser

    user = getUserByAuthToken(request)

    userUpdateFields = account_update_params
    newPassword = userUpdateFields[:password]
    currentPassword = userUpdateFields[:current_password]

    if(!newPassword.blank?)
      passwordCheck = false
      if(!currentPassword.blank?)
        passwordCheck = user.valid_password?(currentPassword)
      end
      if(!passwordCheck)
        logger.error "The current password specified was not valid, giving 422 response"
        render :status => :unprocessable_entity, :json => I18n.t("422response_current_password_confirmation_failure")
        return
      end
    end

    update_resource(user, userUpdateFields)

    if !user.save
      render :status => 422, :json => I18n.t("422response_unable_to_update_user")
      return
    end

    theResponse = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token}
    render :status => 200, :json => theResponse
  end

  ##################
  # Create user
  # POST /user
  # curl -v -X PUT http://127.0.0.1:3000/user -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
  ##################
  def create
   	build_resource(sign_up_params)
    if resource.save
      theResponse = { :id => resource.id, :email => resource.email, :authentication_token => resource.authentication_token}
      render :status => 200, :json => theResponse
	 	else
	   	render :json => resource.errors, :status => :unprocessable_entity
		end
  end

  ##################
  # Delete the user
  # DELETE /user/deleteUser
  # This will put 'now' as 'deleted_at' in the user object and set 'invactive' to true.
  # If the user already was deleted, the client will get a 403 in the authentication filter
  # curl -v -X DELETE http://127.0.0.1:3000/user -H "Content-Type: application/json" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS"
  ##################
  def delete
    user = getUserByAuthToken(request)
    user.soft_delete
    head :no_content
  end


  ##################
  # Trigger the sending of a confirmation email for the user
  # POST /user/confirmation
  # 412 - If the email address of the user if already confirmed
  # curl -v -X PUT http://127.0.0.1:3000/user/confirmation -H "Content-Length: 0" -H "Accept: application/json" -H "Content-Type: application/json" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS"
  ##################
  def triggerConfirmation

    user = getUserByAuthToken(request)
    user.resend_confirmation_instructions

    if(user.errors.blank?)
      logger.info "Email confirmation instructions were sent for user #{user.email}\n"
      render :status => 200, :json => "Email confirmation instructions emailed."
    else
      if(!user.errors.messages[:email].blank?)
        logger.error "Devise said: \"#{user.errors.messages[:email]}\". Interpret as no email confirmation pending for #{user.email} (user id: #{user.id}), instructions will not be emailed.\n"
        render :status => 412, :json => {:error => "No email confirmation pending"}.to_json
      else
        logger.error "Unexpected error encountered when attempting to send confirmation instructions for #{user.email}. Error: #{user.errors.inspect}.\n"
        render :status => 500, :json => {:error => I18n.t("500response_internal_server_error")}.to_json
      end
    end
  end

end
