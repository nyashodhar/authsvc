
class AuthenticationsController < Devise::RegistrationsController

  #
  # Without this, we get the 'missing authenticity token error' on every request
  #
  skip_before_action :verify_authenticity_token, :only => :create

  respond_to :json
  def create

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
