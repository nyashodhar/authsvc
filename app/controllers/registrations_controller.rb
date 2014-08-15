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
  skip_before_action :verify_authenticity_token, :only => [:create, :editUser, :delete, :triggerConfirmation, :triggerPasswordReset]

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

    the_response = nil

    if(!userUpdateFields[:email].blank? && !user.email.downcase.eql?(userUpdateFields[:email].downcase))
      logger.info "The request changes the email from #{user.email} to #{userUpdateFields[:email].downcase}. Email confirmation instructions will be sent.\n"

      the_response = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token}

      enable_test_hooks = Rails.application.config.enable_test_hooks
      if(enable_test_hooks)

        #
        # Hook for integration test: The email was changed and an email with confirmation
        # instruction was sent, capture the one time generated clear-text token
        # and include it in the JSON response. This makes it possible to create integration
        # tests for the email confirmation step.
        #

        raw_token = user.instance_variable_get("@raw_confirmation_token")
        logger.info "Including raw confirmation token in response: #{raw_token}\n"
        the_response[:confirmation_token] = raw_token
      end

    else
      the_response = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token}
    end

    render :status => 200, :json => the_response

  end

  ##################
  # Create user
  # POST /user
  # curl -v -X POST http://127.0.0.1:3000/user -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
  ##################
  def create

    build_resource(sign_up_params)

    if resource.save

      logger.info "User #{resource.email} has been created.\n"
      the_response = { :id => resource.id, :email => resource.email}
      enable_test_hooks = Rails.application.config.enable_test_hooks

      if(enable_test_hooks)

        #
        # Include the confirmation token that is sent in the confirmation
        # instruction email in the JSON response. This allows for easy
        # integration testing of the email confirmation for newly signed up
        # users.
        #

        raw_token = resource.instance_variable_get("@raw_confirmation_token")
        logger.info "Including raw confirmation token in response: #{raw_token}\n"
        the_response[:confirmation_token] = raw_token
      end

      render :status => 200, :json => the_response
    else
      logger.info "Could not create a user with email #{resource.email}\n"
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
  # POST /user/email/confirmation
  # 412 - If the email address of the user if already confirmed
  # curl -v -X POST http://127.0.0.1:3000/user/email/confirmation -H "Content-Length: 0" -H "Accept: application/json" -H "Content-Type: application/json" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS"
  ##################
  def triggerConfirmation

    user = getUserByAuthToken(request)
    user.resend_confirmation_instructions

    if(user.errors.blank?)
      logger.info "Email confirmation instructions were sent for user #{user.email}\n"
      raw_token = user.instance_variable_get("@raw_confirmation_token")

      the_response = { :confirmation_sent_at => user.confirmation_sent_at }

      enable_test_hooks = Rails.application.config.enable_test_hooks
      if(enable_test_hooks)
        # Assume we're in test environment - add hook in response to enable testing
        logger.info "Including raw confirmation token in response: #{raw_token}\n"
        the_response[:confirmation_token] = raw_token
      end

      render :status => 201, :json => the_response
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


  ##################
  # Trigger the sending of an email containing instructions on how to reset the password
  #
  # This API is PUBLIC!! We therefore can't allow it to be used as a means of
  # determining which userids are valid and which are not.
  #
  # This API should therefore ALWAYS return a 201 response to the client even if there
  # was actually no user found for the token and no reset instruction email was sent.
  #
  # POST /user/password/reset
  # 422 - If the request did not specify an email address
  # 201 - If the user for email could not be found
  # 201 - If the user for the email could not be found
  # 500 - If the user for email could be found, but there was an unexpected error when
  #       sending the reset instruction
  #
  # curl -v -X POST http://127.0.0.1:3000/user/password/reset -H "Accept: application/json" -H "Content-Type: application/json" -d '{"email":"test4@example.com"}'
  ##################
  def triggerPasswordReset

    email = params[:email]

    if(email.blank?)
      logger.info "No email specified when trying to trigger password reset email\n"
      render :status => :unprocessable_entity, :json => {:error => I18n.t("422response_no_email_specified")}
      return
    end

    user = User.find_by_email(email)
    if(user.blank?)
      logger.error "No user found for email #{email}, we will send fake reset response\n"
      raw, enc = Devise.token_generator.generate(User, :reset_password_token)
      the_response = { :email => email, :reset_password_sent_at => Time.now.utc}
      render :status => 201, :json => the_response
      return
    end

    # Try to generate the real password reset email
    raw_reset_token = user.send_reset_password_instructions

    if(!user.errors.empty?)
      logger.info "Error when trying to send password reset instructions for user #{email}: #{user.errors.inspect}\n"
      render :status => 500, :json => {:error => I18n.t("500response_internal_server_error")}.to_json
      return
    end

    # Everything worked out, give JSON response for successful outcome

    the_response = { :email => user.email, :reset_password_sent_at => user.reset_password_sent_at}

    enable_test_hooks = Rails.application.config.enable_test_hooks
    if(enable_test_hooks)
      # Assume we're in test environment - add hook in response to enable testing
      logger.info "Including raw confirmation token in response: #{raw_reset_token}\n"
      the_response[:reset_password_token] = raw_reset_token
    end

    render :status => 201, :json => the_response
  end
end
