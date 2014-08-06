#######################################################
#
# The purpose of this controller is to ensure that
# requests that can't be routed to get a proper
# 'not found' response, either a 404 JSON or a
# Page not Found HTML page.
#
#######################################################
class ErrorsController < ActionController::Base
  def not_found
    if(request.format == "text/html")
      logger.error "Custom 404 Handler: No route found for path #{request.path}, rendering HTML."
      render :status => 404, template: "users/errors/page_not_found"
    else
      logger.error "Custom 404 Handler: No route found for path #{request.path}, rendering JSON."
      render :status => 404, :json => {:error => I18n.t("404response_resource_not_found")}.to_json
    end
  end
end