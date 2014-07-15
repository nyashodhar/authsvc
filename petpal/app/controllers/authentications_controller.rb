
class AuthenticationsController < Devise::RegistrationsController

  #before_filter :authenticate_user!

  prepend_before_filter :authenticate_scope!, only: [:foo]

  #
  # Without this, we get the 'missing authenticity token error' on every request
  #
  skip_before_action :verify_authenticity_token, :only => :create

  respond_to :json

  def edit
    STDOUT.write "HELLO THERE\n"

    email = "test\@example.com"

    foo = User.find_by_email(email)

    render :json => foo
  end

  def foo

  end

  def create

    ################ ACCOUNT SERVICE (related to Devise::RegistrationsController)
    #
    # Create user
    # POST /user/register
    #
    # Update user
    # PUT /user/register/edit
    #
    # Delete user
    # DELETE /user/register
    #
    ################ AUTH SERVICE (related to Devise::SessionsController)
    #
    # Sign in:
    # POST /user/login
    # curl -X POST http://127.0.0.1:3000/user/login.json -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234"}}' > /Users/per/foo-login.html    #
    #
    # Sign out:
    # DELETE /user/logout
    # curl -X DELETE http://127.0.0.1:3000/user/logout.json -H "X-User-Email: test@example.com" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json" > /Users/per/foo-logout.html
    #
    # Verify token
    # Speculation: GET /user/auth/
    #
    ############### ACCOUNT SERVICE (our own non-devise controller...)
    #
    # Get user by email
    # GET /user/$email
    #
    # Get user by id
    # GET /user/#id -H "authToken: #$%$#@"
    #
    ############### USER DATA SERVICE
    #
    # Get my encounters
    # GET
    #
    #


    #
    # This command can create a new user:
    #
    # curl -v -X POST http://127.0.0.1:3000/auth/register.json -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234", "password_confirmation":"Test1234"}}' > /Users/per/foobar.html
    #
    # Hints found here:
    #
    # Hint on controller config:
    # 
    #  http://stackoverflow.com/questions/3546289/override-devise-registrations-controller
    #
    # Hint on what JSON to use when posting a user for signup:
    #
    #  http://stackoverflow.com/questions/8841946/create-user-in-devise-from-json
    #
    # Problem with forbidden attributes:
    # 
    #  http://stackoverflow.com/questions/22753243/activemodelforbiddenattributeserror-while-using-devise-for-registeration
    #

	  respond_to do |format|
	    format.json {

        	build_resource(sign_up_params)

            #STDOUT.write "HELLO\n"
            #STDOUT.write "resource_name=#{resource_name}\n"
            #STDOUT.write "resource.email=#{resource.email}\n"
            #STDOUT.write "resource=#{resource}\n"

	        if resource.save
	          render :status => 200, :json => resource
	      	else
	        	render :json => resource.errors, :status => :unprocessable_entity
		    end
	    }
	end

  end

end
