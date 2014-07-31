Rails.application.routes.draw do

  get 'profiles/secureLookup', to:'profiles#secureLookup', as: 'secureLookup'

  # JSON handlers for 404, 500 to prevent them from being HTML-based.

  get "404", :to => "errors#not_found"
  get "500", :to => "errors#exception"

  devise_scope :user do

    #RegistrationsController:
    #===============================
    get 'user', to: 'registrations#find', as: 'find'
    put 'user', to: 'registrations#editUser', as: 'editUser'
    post 'user', to: 'registrations#create', as: 'create'
    delete 'user', to: 'registrations#delete', as: 'delete'

    #SessionsController:
    #===============================
    get 'user/auth', to: 'sessions#verify', as: 'verify'
    post 'user/auth', to: 'sessions#login', as: 'login'
    delete 'user/auth', to: 'sessions#logout', as: 'logout'
  end

  #devise_for :users, :controllers => {:registrations => "registrations", :sessions => "sessions" }
  devise_for :users

  ##devise_for :users, :controllers => {:registrations => "registrations"}

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
