################ ACCOUNT SERVICE (related to Devise::RegistrationsController)
#
# TODO: Implement and test this
# Update user
# PUT /user/register
# curl -v -X PUT http://127.0.0.1:3000/user/register.json -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
#
# TODO: Implement a delete request handler
# Delete user
# DELETE /user/register
#
# TODO: Maybe this will be used in other controller, e.g. ProfilesController
# Get user by email
# GET /user/$email
#
# Get user by id
# GET /user/#id -H "authToken: #$%$#@"
#
##################

class RegistrationsController < Devise::RegistrationsController

  # Required to for devise to not require the presence of an authenticity token
  skip_before_action :verify_authenticity_token, :only => [:create, :update, :editUser]

  respond_to :json

  #################
  # Look up user
  # GET /user/register/edit
  # curl -v -X GET http://127.0.0.1:3000/user/lookup -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS"
  #################
  def lookup
    userInfo = verifyToken(request)
    if(!userInfo.blank?)
      # TODO: Refresh the expiration time of the token
      render :status => 200, :json => userInfo
    end
  end

  ##################
  # Update user
  # PUT /user/register
  # curl -v -X PUT http://127.0.0.1:3000/user/register.json -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}'
  ##################
  def editUser

    STDOUT.write "UPDATE: HELLO\n"

    userInfo = verifyToken(request)
    if(!userInfo.blank?)
      respond_to do |format|
        format.json {

          #STDOUT.write "UPDATE: authenticated userInfo.id: #{userInfo.id}\n"
          user = User.find_by_id(userInfo.id)
          #STDOUT.write "UPDATE: user before update: #{user.inspect}\n"

          ##
          ## TODO: Currently the password can be update without specifying the old
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

  private

  ##################
  # Sends a 403 JSON response if the auth token is not valid.
  # Other methods must check if returned userInfo is blank before proceeding with their processing
  ##################
  def verifyToken(request)

    token = request.headers['X-User-Token']
    userInfo = User.select("id, email").where("authentication_token=?", token).limit(1)
    if(userInfo.blank?)
      render :status => 403, :json => I18n.t("token_verification_failed")
    end
    return userInfo[0]
  end

end
