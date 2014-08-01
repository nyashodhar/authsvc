#######################################################
#
# The purpose of this controller is to ensure that
# requests that encounter unexpected errors receive
# proper JSON responses
#
#######################################################
class ErrorsController < ActionController::Base
  def not_found
    logger.error "Custom 404 Handler: No route found for path #{request.path}."
    render :status => 404, :json => {:error => I18n.t("404response_resource_not_found")}.to_json
  end
end