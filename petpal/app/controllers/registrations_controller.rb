################ ACCOUNT SERVICE (related to Devise::RegistrationsController)
#
# TODO: Implement and test this
# Update user
# PUT /user/register/edit
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

  #prepend_before_filter :authenticate_scope!, only: [:foo]

  # Required to for devise to not require the presence of an authenticity token
  skip_before_action :verify_authenticity_token, :only => :create

  respond_to :json

  #################
  # Look up user
  # GET /user/register/edit
  # curl -v -X GET http://127.0.0.1:3000/user/lookup -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS"
  #################
  def lookup
    token = request.headers['X-User-Token']
    userInfo = User.select("id, email").where("authentication_token=?", token).limit(1)

    if(userInfo == nil)
      render :status => 404, :json => I18n.t("token_verification_failed")
    else
      # TODO: Refresh the expiration time of the token
      render :status => 200, :json => userInfo[0]
    end
  end

  # TODO: Clean up this stuff
  def foo

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

end
