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
  # curl -v -X PUT http://127.0.0.1:3000/user -H "Content-Type: application/json" -d '{"user":{"email":"test4@example.com", "password":"Test1234", "current_password":"Test1234"}}' -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS"
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
        logger.error "The current password specified was not valid"
        render :status => :unprocessable_entity, :json => {:error => I18n.t("422response_current_password_confirmation_failure")}
        return
      end
    end

    update_resource(user, userUpdateFields)

    if !user.save
      render :status => :unprocessable_entity, :json => {:error => I18n.t("422response_unable_to_update_user")}
      return
    end

    #
    # If the email was changed and an email with confirmation instruction was sent,
    # then this is our one and only time to capture the one time generated clear-text
    # token. We will capture it here and include it in the JSON response. This makes
    # it possible to create integration tests for the email confirmation step!
    #

    theResponse = nil

    if(!userUpdateFields[:email].blank? && !user.email.downcase.eql?(userUpdateFields[:email].downcase))
      logger.info "The request changes the email from #{user.email} to #{userUpdateFields[:email].downcase}. Email confirmation instructions will be sent and confirmation token will be included in the JSON response.\n"
      raw_token = user.instance_variable_get("@raw_confirmation_token")
      theResponse = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token, :confirmation_token => raw_token}
    else
      theResponse = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token}
    end

    render :status => 200, :json => theResponse

  end

  ##################
  # Create user
  # POST /user
  # curl -v -X POST http://127.0.0.1:3000/user -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
  ##################
  def create
   	build_resource(sign_up_params)

    if resource.save

      #
      # Include the confirmation token that is sent in the confirmation
      # instruction email in the JSON response. This allows for easy
      # integration testing of the email confirmation for newly signed up
      # users.
      #

      raw_token = resource.instance_variable_get("@raw_confirmation_token")
      theResponse = { :id => resource.id, :email => resource.email, :confirmation_token => raw_token}
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
      raw_token = user.instance_variable_get("@raw_confirmation_token")
      render :status => 200, :json => {:confirmation_token => raw_token}.to_json
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
