///<reference path="../../../headers/common.d.ts" />

import angular from 'angular';
import config from 'app/core/config';
import _ from 'lodash';
import $ from 'jquery';
import coreModule from '../../core_module';
import appEvents from 'app/core/app_events';

export class SearchCtrl {
  isOpen: boolean;
  query: any;
  giveSearchFocus: number;
  selectedIndex: number;
  results: any;
  temResultsQuery: any;
  currentSearchId: number;
  tagsMode: boolean;
  showImport: boolean;
  dismiss: any;
  ignoreClose: any;

  /** @ngInject */
  constructor(private $scope, private $location, private $timeout, private backendSrv, private contextSrv, private $rootScope) {
    $rootScope.onAppEvent('show-dash-search', this.openSearch.bind(this), $scope);
    $rootScope.onAppEvent('hide-dash-search', this.closeSearch.bind(this), $scope);
  }

  closeSearch() {
    this.isOpen = this.ignoreClose;
  }

  openSearch(evt, payload) {
    if (this.isOpen) {
      this.isOpen = false;
      return;
    }

    this.isOpen = true;
    this.giveSearchFocus = 0;
    this.selectedIndex = -1;
    this.results = [];
    this.temResultsQuery = [];
    this.query = { query: '', tag: [], starred: false };
    this.currentSearchId = 0;
    this.ignoreClose = true;

    if (payload && payload.starred) {
      this.query.starred = true;
    }

    if (payload && payload.tagsMode) {
      return this.$timeout(() => {
        this.ignoreClose = false;
        this.giveSearchFocus = this.giveSearchFocus + 1;
        this.getTags();
      }, 100);
    }

    this.$timeout(() => {
      this.ignoreClose = false;
      this.giveSearchFocus = this.giveSearchFocus + 1;
      this.search();
    }, 100);
  }

  keyDown(evt) {
    if (evt.keyCode === 27) {
      this.closeSearch();
    }
    if (evt.keyCode === 40) {
      this.moveSelection(1);
    }
    if (evt.keyCode === 38) {
      this.moveSelection(-1);
    }
    if (evt.keyCode === 13) {
      if (this.$scope.tagMode) {
        var tag = this.results[this.selectedIndex];
        if (tag) {
          this.filterByTag(tag.term, null);
        }
        return;
      }

      var selectedDash = this.results[this.selectedIndex];
      if (selectedDash) {
        this.$location.search({});
        this.$location.path(selectedDash.url);
      }
    }
  }

  moveSelection(direction) {
    var max = (this.results || []).length;
    var newIndex = this.selectedIndex + direction;
    this.selectedIndex = ((newIndex %= max) < 0) ? newIndex + max : newIndex;
  }

  searchDashboards() {
    this.tagsMode = false;
    this.currentSearchId = this.currentSearchId + 1;
    var localSearchId = this.currentSearchId;

    return this.backendSrv.search(this.query).then((results) => {
      if (localSearchId < this.currentSearchId) { return; }
      this.results = [];
      this.temResultsQuery = _.map(results, function(dash) {
        dash.url = 'dashboard/' + dash.uri;
        return dash;
      });
      var controlStop = 0;
      var tempResulstQueryInitialSize = this.temResultsQuery.length;


      for (var i = 0; i<this.temResultsQuery.length; i++) {
        var typeSlug = this.temResultsQuery[i].uri;
        var resd = typeSlug.split("/");
        this.backendSrv.getDashboard(resd[0], resd[1]).then((results) => {
          controlStop++;
          if (results.dashboard.hideDashboard !== true) {

            for (var t = 0; t < this.temResultsQuery.length; t++) {
              if (this.temResultsQuery[t].id === results.dashboard.id) {
                this.results.push(this.temResultsQuery[t]);
                break;
              }
            }
          }
          if (controlStop === tempResulstQueryInitialSize) {
            if (this.queryHasNoFilters()) {
              this.results.unshift({title: 'Home', url: config.appSubUrl + '/', type: 'dash-home'});
            }
          }
        });
      }

      if (tempResulstQueryInitialSize ===0) {
        if (this.queryHasNoFilters()) {
          this.results.unshift({title: 'Home', url: config.appSubUrl + '/', type: 'dash-home'});
        }
      }
    });
  }



  queryHasNoFilters() {
    var query = this.query;
    return query.query === '' && query.starred === false && query.tag.length === 0;
  };

  filterByTag(tag, evt) {
    this.query.tag.push(tag);
    this.search();
    this.giveSearchFocus = this.giveSearchFocus + 1;
    if (evt) {
      evt.stopPropagation();
      evt.preventDefault();
    }
  };

  removeTag(tag, evt) {
    this.query.tag = _.without(this.query.tag, tag);
    this.search();
    this.giveSearchFocus = this.giveSearchFocus + 1;
    evt.stopPropagation();
    evt.preventDefault();
  };

  getTags() {
    return this.backendSrv.get('/api/dashboards/tags').then((results) => {
      this.tagsMode = !this.tagsMode;
      this.results = results;
      this.giveSearchFocus = this.giveSearchFocus + 1;
      if ( !this.tagsMode ) {
        this.search();
      }
    });
  };

  showStarred() {
    this.query.starred = !this.query.starred;
    this.giveSearchFocus = this.giveSearchFocus + 1;
    this.search();
  };

  search() {
    this.showImport = false;
    this.selectedIndex = 0;
    this.searchDashboards();
  };

  searchOnlyVisible(single){
      var typeSlug = single.uri;
      var resd = typeSlug.split("/");
      var sing = this.backendSrv.getDashboard(resd[0],resd[1]);

      return sing.then(function(result) {
        if ( result.dashboard.hideDashboard === true ) {
          return single;
        }
      });
  }

}

export function searchDirective() {
  return {
    restrict: 'E',
    templateUrl: 'public/app/core/components/search/search.html',
    controller: SearchCtrl,
    bindToController: true,
    controllerAs: 'ctrl',
  };
}

coreModule.directive('dashboardSearch', searchDirective);
