ActionController::Routing::Routes.draw do |map|
  map.resources :projects

  map.resources :users

  map.resources :reviews

  map.resources :mappings

  map.resources :margin_notes

  map.resources :concepts

  map.resources :ontologies
  
  map.resources :login
  
  map.resources :admin
  
  # The priority is based upon order of creation: first created -> highest priority.
  
  # Sample of regular route:

  # Keep in mind you can assign values other than :controller and :action

  # Sample of named route:
 
  # This route can be invoked with purchase_url(:id => product.id)

  # You can have the root of your site routed by hooking up '' 
  # -- just remember to delete public/index.html.
   map.connect '', :controller => "home"

  # Allow downloading Web Service WSDL as a file with an extension
  # instead of a file named 'wsdl'
  
  map.connect '/feedback',:controller=>'home',:action=>'feedback'
  map.connect '/annotator',:controller=>'home',:action=>'annotate'
  map.connect '/resources',:controller =>'home',:action=>'all_resources'
  map.connect '/recommender',:controller =>'home',:action=>'recommender'
  map.connect '/exhibit/:ontology/:id',:controller=>'concepts',:action=>'exhibit'
  map.connect '/ontologies/view/edit/:id', :controller => 'ontologies', :action => 'edit_view', :requirements => { :id => %r([^/?]+) }
  map.connect '/ontologies/view/new/:id', :controller => 'ontologies', :action => 'new_view'
  map.upload_mappings '/upload/mapping',:controller=>'mappings',:action=>'upload'
  map.process_mappings '/process/mapping',:controller=>'mappings',:action=>'process_mappings'
  map.connect ':controller/service.wsdl', :action => 'wsdl'
  map.mapping_count '/mappings/count/:ontology',:controller=>'mappings',:action=>'count'
  map.obrpage '/respage/',:controller=>'resources',:action=>'page'

  map.mapping '/mappings/service/:ontology/:id',:controller=>'mappings',:action=>'service'

  map.notes_ont 'notes/ont/:ontology/:id',:controller=>'margin_notes',:action=>'ont_service'
  map.notes_ver 'notes/ver/:ontology/:id',:controller=>'margin_notes',:action=>'ver_service'

  map.obr_details '/res_details/:id',:controller=>'resources',:action=>'details'
  map.obr '/resources/:ontology/:id',:controller=>'resources',:action=>'show'
  
  map.ajax '/ajax/',:controller=>'ajax_proxy',:action=>'get'  
  map.logout '/logout',:controller=>'login',:action=>'destroy'
  map.lost_pass '/lost_pass',:controller=>'login',:action=>'lost_password'
  map.visualize '/visualize/:ontology', :controller=>'ontologies', :action =>'visualize',:requirements => { :ontology => %r([^/?]+) }
  map.uri '/visualize/:ontology/:id', :controller => 'concepts', :action => 'show',:requirements => { :id => %r([^/?]+) }
  map.visualize_concept '/visualize', :controller=>'ontologies', :action =>'visualize',:requirements => { :ontology => %r([^/?]+), :id => %r([^/?]+),
                                                                                                          :ontologyid => %r([^/?]+), :conceptid => %r([^/?]+) }
  map.connect '/ajax_concepts/:ontology/', :controller => 'concepts', :action => 'show', :requirements => { :id => %r([^/?]+) }

  map.virtual_ont '/virtual/:ontology', :controller => 'ontologies', :action => 'virtual',:requirements => { :ontology => %r([^/?]+) ,:id => %r([^/?]+) }
  map.virtual '/virtual/:ontology/:id', :controller => 'concepts', :action => 'virtual',:requirements => { :ontology => %r([^/?]+) ,:id => %r([^/?]+) }
  
  #map.ontology '/ontology/:ontology', :controller => 'ontologies', :action => 'show',:requirements => { :ontology => %r([^/?]+) }
  map.remove_tab '/tab/remove/:ontology',:controller=>'history',:action=>'remove'
  map.update_tab '/tab/update/:ontology/:concept',:controller=>'history',:action=>'update'

  # Redirects from old URL locations
  map.connect '/annotate', :controller=>'redirect', :url=>'/annotator'
  map.connect '/all_resources', :controller =>'redirect', :url=>'/resources'
  map.connect '/visconcepts/:ontology/', :controller =>'redirect', :url=>'/visualize/'

  # Install the default route as the lowest priority.
  map.connect ':controller/:action/:id.:format'
  map.connect ':controller/:action/:id'
  map.jam 'jambalaya/:ontology/:id', :controller => 'visual', :action => 'jam'
end
