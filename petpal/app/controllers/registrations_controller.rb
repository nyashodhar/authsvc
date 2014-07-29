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
  # GET /user/register/edit
  # If the user already was deleted, the user will get a 403 error passed along from
  # the verifyToken method
  # curl -v -X GET http://127.0.0.1:3000/user/lookup -H "X-User-Token: zZGGxQYUcVxHDXfxVysS"
  #################
  def lookup
    userInfo = getLoggedInUser(request)
    render :status => 200, :json => userInfo
  end

  ##################
  # Update user
  # PUT /user/editUser
  # If the user already was deleted, the user will get a 403 error passed along from
  # the verifyToken method
  # curl -v -X PUT http://127.0.0.1:3000/user/editUser -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
  ##################
  def editUser

    ##
    ## TODO: Currently the password can be updated without specifying the old
    ## password and verifying that the old password 'checks out'
    ##

    user = getUserByAuthToken(request)
    update_resource(user, account_update_params)
    user.save
    render :status => 200, :json => user
  end

  ##################
  # Create user
  # POST /user/register
  # curl -v -X POST http://127.0.0.1:3000/user/register -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
  ##################
  def create
   	build_resource(sign_up_params)
    if resource.save
      render :status => 200, :json => resource
	 	else
	   	render :json => resource.errors, :status => :unprocessable_entity
		end
  end

  ##################
  # Delete the user - This will put 'now' as 'deleted_at' in the user object
  # and set 'invactive' to true.
  # If the user already was deleted, the client will get a 403 in the authentication filter
  # curl -v -X DELETE http://127.0.0.1:3000/user/deleteUser.json -H "Content-Type: application/json" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS"
  ##################
  def deleteUser
    user = getUserByAuthToken(request)
    user.soft_delete
    render :status => 204, :json => ""
  end

end
