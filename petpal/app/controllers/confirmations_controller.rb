########################################################
#
# This class is the entry point for links clicked in
# emails containing confirmation instructions
#
# This controller deals with text/html, not JSON.
#
########################################################
class ConfirmationsController < Devise::ConfirmationsController

  # Required to for devise to not require the presence of an authenticity token
  #skip_before_action :verify_authenticity_token, :only => [:login, :logout]

  #prepend_before_filter :require_no_authentication, :only => [:login]
  include Devise::Controllers::Helpers

  #respond_to :json

  ################
  # This action processes an email confirmation from a user.
  #
  # The URLs look like this:
  #
  #    GET /users/confirmation?confirmation_token=abcdef
  #
  # The contract is:
  # 1) If confirmation token is not valid, give a 404 response with an error page view
  # 2) If the confirmation token is valid and user's confirmation record was updated,
  #    do a 201 to a 'thank you for confirming page'
  # 3) If an unexpected error happens, we should do a 200 response to an 'Oooops' page.
  ################
  def processConfirmation

    sdfasfasfa sadfasdf


    self.resource = resource_class.confirm_by_token(params[:confirmation_token])

    if resource.errors.empty?
      logger.info "The user's confirmation was processed successfully\n"
      render :status => 201, template: "users/confirmations/confirmation_successful"
    else
      logger.info "The user's confirmation could not be processed successfully, errors: #{resource.errors.messages.inspect}\n"
      render :status => 404, template: "users/confirmations/confirmation_failed"
    end
  end
end