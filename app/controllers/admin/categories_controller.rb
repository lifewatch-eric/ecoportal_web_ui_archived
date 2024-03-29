class Admin::CategoriesController < ApplicationController

  layout :determine_layout
  before_action :unescape_id, only: [:edit, :show, :update, :destroy]
  before_action :authorize_admin

  CATEGORIES_URL = "#{LinkedData::Client.settings.rest_url}/categories"

  def index
    response = _categories
    render :json => response
  end

  def new
    @category = LinkedData::Client::Models::Category.new

    respond_to do |format|
      format.html { render "new", :layout => false }
    end
  end

  def edit
    @category = LinkedData::Client::Models::Category.find_by_acronym(params[:id]).first

    respond_to do |format|
      format.html { render "edit", :layout => false }
    end
  end

  def create
    response = { errors: '', success: '' }
    start = Time.now
    begin
      category = LinkedData::Client::Models::Category.new(values: category_params)
      category_saved = category.save
      if category_saved && category_saved.errors
        response[:errors] = response_errors(category_saved)
      else
        response[:success] = "category successfully created in  #{Time.now - start}s"
      end
    rescue Exception => e
      response[:errors] = "Problem creating the category  - #{e.message}"
    end
    render json: response, status: (response[:errors] == '' ? :created : :internal_server_error)

  end

  def update
    response = { errors: '', success: ''}
    start = Time.now
    begin
      category = LinkedData::Client::Models::Category.find_by_acronym(params[:id]).first
      category.update_from_params(category_params)
      category_update = category.update
      if category_update && category_update.errors
        response[:errors] = response_errors(category_update)
      else
        response[:success] = "category successfully updated in  #{Time.now - start}s"
      end
    rescue Exception => e
      response[:errors] = "Problem updating the category - #{e.message}"
    end
    render json: response, status: (response[:errors] == '' ? :ok : :internal_server_error)
  end

  def destroy
    response = { errors: '', success: ''}
    start = Time.now
    begin
      category = LinkedData::Client::Models::Category.find_by_acronym(params[:id]).first
      error_response = category.delete

      if error_response
        response[:errors] = response_errors(error_response)
      else
        response[:success] = "category successfully deleted in  #{Time.now - start}s"
      end
    rescue Exception => e
      response[:errors] = "Problem deleting the category - #{e.message}"
    end
    render json: response, status: (response[:errors] == '' ? :ok : :internal_server_error)
  end

  private

  def unescape_id
    params[:id] = CGI.unescape(params[:id])
  end

  def category_params
    params.require(:category).permit(:acronym, :name, :description, :parentCategory).to_h()
  end

  def _categories
    response = { categories: Hash.new, errors: '', success: '' }
    start = Time.now
    begin
      response[:categories] = JSON.parse(LinkedData::Client::HTTP.get(CATEGORIES_URL, { include: 'all' }, raw: true))

      response[:success] = "categories successfully retrieved in  #{Time.now - start}s"
      LOG.add :debug, "Categories - retrieved #{response[:categories].length} groups in #{Time.now - start}s"
    rescue Exception => e
      response[:errors] = "Problem retrieving categories  - #{e.message}"
    end
    response
  end
end
