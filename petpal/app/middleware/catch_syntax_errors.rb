####################################################
#
# This class ensures that all syntax errors don't
# cause HTML 500 responses
#
####################################################
class CatchSyntaxErrors
  def initialize(app)
    @app = app
    @logger = Rails.application.config.logger
  end

  def call(env)
    begin
      @app.call(env)
    rescue SyntaxError => error
      trace = error.backtrace[0,10].join("\n")
      @logger.error "CatchSyntaxErrors: Error: #{error.class.name} : #{error.message}. Trace:\n#{trace}\n"
      error_output = I18n.t("500response_internal_server_error")

      return [
          500, { "Content-Type" => "application/json" },
          [ { error: error_output }.to_json ]
      ]
    end
  end
end