Rails.application.routes.draw do

  devise_scope :user do

    # RegistrationsController:
    #===============================
    get 'user', to: 'registrations#find', as: 'find'
    put 'user', to: 'registrations#editUser', as: 'editUser'
    post 'user', to: 'registrations#create', as: 'create'
    delete 'user', to: 'registrations#delete', as: 'delete'
    post 'user/email/confirmation', to: 'registrations#triggerConfirmation', as: 'triggerConfirmation'
    post 'user/password/reset', to: 'registrations#triggerPasswordReset', as: 'triggerPasswordReset'

    # SessionsController:
    #===============================
    get 'user/auth', to: 'sessions#verify', as: 'verify'
    post 'user/auth', to: 'sessions#login', as: 'login'
    delete 'user/auth', to: 'sessions#logout', as: 'logout'

    # ConfirmationsController:
    #===============================
    get 'users/confirmation', to: 'confirmations#processConfirmation', as: 'processConfirmation'

    # PasswordsController:
    #===============================
    get 'users/password/edit', to: 'passwords#edit', as: 'edit'
    put 'users/password', to: 'passwords#update', as: 'update'
    get 'users/password/success', to: 'passwords#showResetSuccess', as: 'showResetSuccess'

    match "*path", to: "errors#not_found", via: :all
  end

  get "/", to: "deployments#status", as: 'status'

  devise_for :users

  # The priority is based upon order of creation: first created -> highest priority.
  # See how all your routes lay out with "rake routes".

  # You can have the root of your site routed with "root"
  # root 'welcome#index'

  # Example of regular route:
  #   get 'products/:id' => 'catalog#view'

  # Example of named route that can be invoked with purchase_url(id: product.id)
  #   get 'products/:id/purchase' => 'catalog#purchase', as: :purchase

  # Example resource route (maps HTTP verbs to controller actions automatically):
  #   resources :products

  # Example resource route with options:
  #   resources :products do
  #     member do
  #       get 'short'
  #       post 'toggle'
  #     end
  #
  #     collection do
  #       get 'sold'
  #     end
  #   end

  # Example resource route with sub-resources:
  #   resources :products do
  #     resources :comments, :sales
  #     resource :seller
  #   end

  # Example resource route with more complex sub-resources:
  #   resources :products do
  #     resources :comments
  #     resources :sales do
  #       get 'recent', on: :collection
  #     end
  #   end

  # Example resource route with concerns:
  #   concern :toggleable do
  #     post 'toggle'
  #   end
  #   resources :posts, concerns: :toggleable
  #   resources :photos, concerns: :toggleable

  # Example resource route within a namespace:
  #   namespace :admin do
  #     # Directs /admin/products/* to Admin::ProductsController
  #     # (app/controllers/admin/products_controller.rb)
  #     resources :products
  #   end
end
