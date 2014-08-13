class ApplicationController < ActionController::Base

  # This is for simple_token_authentication
  acts_as_token_authentication_handler_for User

  # Prevent CSRF attacks by raising an exceptions Per-Yash-Will
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  rescue_from StandardError do |e|
    error(e)
  end

  def error(e)
    trace = e.backtrace[0,10].join("\n")
    logger.error "Custom error handler - Error: #{e.class.name} : #{e.message}, Trace: #{trace}\n"
    request_format = request.format
    if(request.format == "text/html")
      # Show a webpage if it was an HTML request
      render :status => 200, template: "users/errors/unexpected_error"
    else
      # Give JSON 500 response if it was a JSON request
      render :status => 500, :json => {:error => I18n.t("500response_internal_server_error")}.to_json
    end
  end
end
