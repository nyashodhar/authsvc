########################################################
#
# This class is the entry point for links clicked in
# emails containing instructions for password reset
#
# This controller deals with text/html, not JSON.
#
########################################################
class PasswordsController < Devise::PasswordsController

  #####################################
  # Overriding this to customize
  # which page is redirected to on success
  #
  # The devise impl is also signing the
  # user in, which we don't want either.
  #
  # PUT /users/password
  #####################################
  def update

    self.resource = resource_class.reset_password_by_token(resource_params)
    yield resource if block_given?

    if resource.errors.empty?
      logger.info "The password reset was successful for user #{resource.email}, redirecting to success view.\n"
      redirect_to(:action => "showResetSuccess")
    else
      logger.error "An error occurred during password reset: #{resource.errors.messages.inspect}\n"
      respond_with resource
    end
  end

  #####################################
  # Overriding this to customize
  # which page is redirected to on success
  #
  # The devise impl is also signing the
  # user in, which we don't want either.
  #
  # GET /users/password/success
  #####################################
  def showResetSuccess
    render :status => 201, template: "users/confirmations/password_reset_successful"
  end

end