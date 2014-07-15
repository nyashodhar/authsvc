

class SessionsController < Devise::SessionsController

  skip_before_action :verify_authenticity_token, :only => [:create, :destroy]

  prepend_before_filter :require_no_authentication, :only => [:create]
  include Devise::Controllers::Helpers

  respond_to :json

  def create
    super
=begin
    self.resource = warden.authenticate!(auth_options)
    sign_in(resource_name, resource)
    resource.reset_authentication_token!
    resource.save!
    render json: {
      auth_token: resource.reset_authentication_token,
      user_role: resource.role
    }
=end
  end

  def destroy
    super
    #sign_out(resource_name)
  end

end