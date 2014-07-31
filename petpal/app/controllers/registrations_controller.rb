###################################
#
# This controller implements account functionality
#
# Create user
# Edit user
# Delete user
# Look up user
#
# All actions in this controller are authenticated via token,
# except create operation.
#
###################################
#
# TODO: Maybe this will be used in other controller, e.g. ProfilesController
# Get user by email
# GET /user/$email
#
###################################

class RegistrationsController < Devise::RegistrationsController

  include ApplicationHelper

  # Required to for devise to not require the presence of an authenticity token
  skip_before_action :verify_authenticity_token, :only => [:create, :update, :editUser, :deleteUser]

  respond_to :json

  #
  # Note: Check if there is a sign-in for the auth token, and that the sign-in
  # is not expired
  #
  before_action :ensureLoggedInAndAuthTokenNotExpired, :only => [:lookup, :editUser, :deleteUser]

  #################
  # Look up user
  # GET /user/lookup
  # If the user already was deleted, the user will get a 403 error passed along from
  # the verifyToken method
  # curl -v -X GET http://127.0.0.1:3000/user/lookup -H "X-User-Token: zZGGxQYUcVxHDXfxVysS"
  #################
  def lookup
    user = getLoggedInUser(request)
    theResponse = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token}
    render :status => 200, :json => theResponse
  end

  #######################################################
  # Update user
  # PUT /user/editUser
  #
  # If the password is being updated, the request will
  # get a 422 if the current password is not provided
  # correctly
  #
  # EXAMPLE:
  # curl -v -X PUT http://127.0.0.1:3000/user/editUser -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "current_password":"Test1234"}}'
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
        logger.info "The current password specified was not valid, giving 422 response"
        render :status => :unprocessable_entity, :json => I18n.t("422response_current_password_confirmation_failure")
        return
      end
    end

    update_resource(user, userUpdateFields)
    user.save
    theResponse = { :id => user.id, :email => user.email, :authentication_token => user.authentication_token}
    render :status => 200, :json => theResponse
  end

  ##################
  # Create user
  # POST /user/register
  # curl -v -X POST http://127.0.0.1:3000/user/register -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
  ##################
  def create
   	build_resource(sign_up_params)
    if resource.save
      theResponse = { :id => resource.id, :email => resource.email, :authentication_token => user.authentication_token}
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
  # curl -v -X DELETE http://127.0.0.1:3000/user/deleteUser -H "Content-Type: application/json" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS"
  ##################
  def deleteUser
    user = getUserByAuthToken(request)
    user.soft_delete
    head :no_content
  end

end
