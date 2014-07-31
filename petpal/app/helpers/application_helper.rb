module ApplicationHelper

  ########################################################################
  # This method is in use ALL PROTECTED APIS.
  #
  # This method verifies that the user is logged in and that the auth token
  # is not expired.
  #
  # If the user is not logged in, this method will give a 401 response
  # and control will not reach the protected controller action.
  #
  # If the user is logged in, but the auth token is expired, this method
  # will give a 401 response and control will not reach the protected
  # controller action.
  #
  # If the user is logged in and the auth token is not expired, this
  # method will allow control to be reach the controller action.
  ########################################################################
  def ensureLoggedInAndAuthTokenNotExpired

    token = request.headers['X-User-Token']
    if(token.blank?)
      logger.info "ensureLoggedInAndAuthTokenNotExpired(): No auth token found in request\n"
      render :status => 401, :json => I18n.t("401response")
      return
    end

    userInfo = User.deleted.merge(User.active).select("id, email", "current_sign_in_at").where("authentication_token=?", token).limit(1)
    theUser = userInfo[0]
    if(theUser.blank?)
      logger.info "ensureLoggedInAndAuthTokenNotExpired(): No sign-in found for auth token #{token}\n"
      render :status => 401, :json => I18n.t("401response")
      return
    end

    #
    # There is a sign-in for this auth token, so we need to ensure
    # the sign-in is not expired
    #

    if(isLoginExpired(theUser))
      logger.info "ensureLoggedInAndAuthTokenNotExpired(): The sign-in for auth token #{token} is expired\n"
      render :status => 401, :json => I18n.t("401response")
      return
    end

    # Things are great, control will now pass to the controller action

  end

  ########################################################################
  # This method is only used for SIGN IN.
  #
  # If the user's auth token is expired at sign-in time, then this method
  # will ensure that a new auth token generation is triggered for the user.
  #
  # This ensures that expired auth tokens are not allowed to linger. If no
  # user is found for the email, then the control is given back to the
  # sign-in controller to fail the login in the normal fashion.
  ########################################################################
  def clearStaleTokenBeforeSignIn

    #
    # Technical Note: It's assumed that this module is included from the controller, and hence the request
    # object is available at this point.
    #

    myTestUserSignParams = User.new(sign_in_params)
    email = myTestUserSignParams.email

    if(email.blank?)
      logger.info "clearStaleTokenBeforeSignIn(): No email specified for sign-in, can't check token staleness.\n"
      render :status => :unprocessable_entity, :json => I18n.t("422response_no_email_specified")
      return
    end

    userInfo = User.deleted.merge(User.active).select("id, email", "current_sign_in_at").where("email=?", email).limit(1)
    theUser = userInfo[0]

    if(theUser.blank?)
      #
      # We couldn't find a user with the given email => Do 401 here.
      # If we don't take action here, devise will actually do a successful sign-in
      #
      logger.info "clearStaleTokenBeforeSignIn(): User could not be found for email #{email}.\n"
      render :status => 401, :json => I18n.t("401response_invalid_email_or_password")
      return
    end

    if(isLoginExpired(theUser))

      logger.info "clearStaleTokenBeforeSignIn(): The sign-in for user #{theUser.id} is expired. Clearing the user's auth token to force new token generation.\n"
      theUserId = theUser.id

      #
      # Note: This actually will trigger an immediate regeneration of a new auth-token
      # by the simple token authentication mechanism!
      #
      User.update(theUserId, :authentication_token => nil)
    end
  end


  ##############################################
  # Retrieves a user object based on the
  # auth token in the request
  ##############################################
  def getUserByAuthToken(request)
    token = request.headers['X-User-Token']
    user = User.find_by_authentication_token(token)
    return user
  end

  ##############################################
  # Removes the current auth token for a user
  ##############################################
  def clearAuthTokenForUser(user)
    User.update(user.id, :authentication_token => nil)
  end

  private

  def isLoginExpired(theUser)

    currentSignInAtActiveSupportTimeWithZone = theUser[:current_sign_in_at]
    if(currentSignInAtActiveSupportTimeWithZone.blank?)
      logger.info "isLoginExpired(): The user #{theUser.id} has never logged in. Treating login as expired.\n"
      return true
    end

    currentSignInAtDateTime = currentSignInAtActiveSupportTimeWithZone.to_datetime

    now = DateTime.now
    tokenAgeDays = now - currentSignInAtDateTime
    tokenAgeMillis = (tokenAgeDays * 24 * 60 * 60 * 1000).to_i

    tokenTTLMS = Rails.application.config.auth_token_ttl_ms

    if(tokenAgeMillis > tokenTTLMS)
      staleTimeMS = tokenAgeMillis - tokenTTLMS
      logger.info "isLoginExpired(): The authentication token for user #{theUser.id} expired #{staleTimeMS} millis ago.\n"
      return true
    end

    return false
  end

end
