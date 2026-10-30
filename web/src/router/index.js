import { createRouter, createWebHashHistory } from 'vue-router'
import Home from '../views/Home.vue'
import CaseView from '../views/CaseView.vue'

// hash URLs: FastAPI serves static files, so a refresh on /case/x would otherwise 404
export default createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', name: 'Home', component: Home },
    { path: '/case/:caseId', name: 'CaseView', component: CaseView, props: true }
  ]
})
