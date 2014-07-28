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

  #################
  # Look up user
  # GET /user/register/edit
  # If the user already was deleted, the user will get a 403 error passed along from
  # the verifyToken method
  # curl -v -X GET http://127.0.0.1:3000/user/lookup -H "X-User-Token: eXcPsqL-19yzxVpYceeF"
  #################
  def lookup

    STDOUT.write "current_user = #{current_user.inspect}\n"
    STDOUT.write "session = #{session.inspect}\n"
    #render :status => 200, :json => "Hola"

    #userInfo = User.find_by_id(session[:user_id]))

    userInfo = getLoggedInUser(request)
    if(!userInfo.blank?)
      # TODO: Refresh the expiration time of the token
      render :status => 200, :json => userInfo
    end
  end

  ##################
  # Update user
  # PUT /user/register
  # If the user already was deleted, the user will get a 403 error passed along from
  # the verifyToken method
  # curl -v -X PUT http://127.0.0.1:3000/user/register.json -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
  ##################
  def editUser

    #STDOUT.write "UPDATE: HELLO\n"

    userInfo = getLoggedInUser(request)
    if(!userInfo.blank?)
      respond_to do |format|
        format.json {

          #STDOUT.write "UPDATE: authenticated userInfo.id: #{userInfo.id}\n"

          #
          # Note: It's OK to no apply the active user scope here, active
          # scope was already applied in verifyToken
          #

          user = User.find_by_id(userInfo.id)
          #STDOUT.write "UPDATE: user before update: #{user.inspect}\n"

          ##
          ## TODO: Currently the password can be updated without specifying the old
          ## password and verifying that the old password 'checks out'
          ##

          update_resource(user, account_update_params)

          #userAfter = User.find_by_id(userInfo.id)
          #STDOUT.write "UPDATE: user after update: #{user.inspect}\n"
        }
      end
      render :status => 200, :json => userInfo
    end
  end

  ##################
  # Create user
  # POST /user/register
  # curl -v -X POST http://127.0.0.1:3000/user/register.json -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
  ##################
  def create
	  respond_to do |format|
	    format.json {
        	build_resource(sign_up_params)

	        if resource.save
	          render :status => 200, :json => resource
	      	else
	        	render :json => resource.errors, :status => :unprocessable_entity
		    end
	    }
	  end
  end

  ##################
  # Delete the user - This will put 'now' as 'deleted_at' in the user object
  # and set 'invactive' to true.
  # If the user already was deleted, the user will get a 403 error passed along from
  # the verifyToken method
  # curl -v -X DELETE http://127.0.0.1:3000/user/register.json -H "Content-Type: application/json" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS"
  ##################
  def deleteUser
    userInfo = getLoggedInUser(request)
    if(!userInfo.blank?)
      user = User.deleted.merge(User.active).find_by_id(userInfo.id)
      user.soft_delete
      render :status => 204, :json => ""
    end
  end

  private

  ##################
  # Sends a 403 JSON response if the auth token is not valid.
  # Other methods must check if returned userInfo is blank before proceeding with their processing
  ##################
  #def verifyToken(request)

    # TODO: We need to have expiring tokens
    # Get the TTL from
    #
    #   Rails.application.config.auth_token_ttl_ms
    #

  #  token = request.headers['X-User-Token']
  #  userInfo = User.deleted.merge(User.active).select("id, email").where("authentication_token=?", token).limit(1)
  #  if(userInfo.blank?)
  #    render :status => 403, :json => I18n.t("token_verification_failed")
  #  end
  #  return userInfo[0]
  #end

end
