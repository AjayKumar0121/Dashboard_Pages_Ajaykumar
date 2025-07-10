document.addEventListener('DOMContentLoaded', async () => {
  const config = {
    apiBaseUrl: 'http://44.223.23.145:3404/api',
    wsUrl: 'ws://44.223.23.145:4500',
    authUrls: {
      login: 'http://44.223.23.145:8012',
      signup: 'http://44.223.23.145:8013/',
      forgotPassword: 'http://44.223.23.145:8010'
    },
    modules: {
      emp_attendance: 'http://44.223.23.145:8051/',
      emp_leave: 'http://44.223.23.145:8037/',
      emp_wfh: 'http://44.223.23.145:8025/',
      emp_payslip: 'http://3.85.61.23:7019/',
      emp_tasks: 'http://44.223.23.145:8045/',
      emp_helpdesk: 'http://44.223.23.145:8049/',
      emp_Onboarding: 'http://44.223.23.145:8039/',
      emp_benefits: 'http://44.223.23.145:8043/',
      emp_Appraisal: 'http://44.223.23.145:8014/',
      emp_notifications: 'http://44.223.23.145:8053/',
      emp_asset: 'http://44.223.23.145:8047/',
      emp_bonus: 'http://44.223.23.145:8055/',
      emp_joblists: 'http://3.85.61.23:8020/',
      emp_claim: 'http://44.223.23.145:8027/',
      emp_offboarding: 'http://44.223.23.145:8041/',
      emp_jobapplication: 'http://44.223.23.145:8031/',
      emp_offerletter: 'http://44.223.23.145:8033/',
      emp_logout: '',
      hr_attendance: 'http://44.223.23.145:8052/',
      hr_leave: 'http://44.223.23.145:8038/',
      hr_wfh: 'http://44.223.23.145:8026/',
      hr_payslip: 'http://3.85.61.23:7020/',
      hr_tasks: 'http://44.223.23.145:8046/',
      hr_helpdesk: 'http://44.223.23.145:8050/',
      hr_Onboarding: 'http://44.223.23.145:8040/',
      hr_employeemanagement: 'http://44.223.23.145:8036/',
      hr_benefits: 'http://44.223.23.145:8044/',
      hr_appraisal: 'http://44.223.23.145:8015/',
      hr_notifications: 'http://44.223.23.145:8054/',
      hr_asset: 'http://44.223.23.145:8048/',
      hr_bonus: 'http://44.223.23.145:8056/',
      hr_joblists: 'http://3.85.61.23:8021/',
      hr_claim: 'http://44.223.23.145:8028/',
      hr_offboarding: 'http://44.223.23.145:8042/',
      hr_jobapplication: 'http://44.223.23.145:8032/',
      hr_logout: ''
    },
    sessionCheckInterval: 300000
  };

  const elements = {
    appBody: document.getElementById('appBody'),
    loginView: document.getElementById('loginView'),
    dashboardView: document.getElementById('dashboardView'),
    loginForm: document.getElementById('loginForm'),
    emailInput: document.getElementById('email'),
    passwordInput: document.getElementById('password'),
    errorMessage: document.getElementById('error-message'),
    eyeIcon: document.getElementById('eyeIcon'),
    loginButton: document.querySelector('.login-button'),
    contentFrame: document.getElementById('contentFrame'),
    avatarSkeleton: document.getElementById('avatarSkeleton'),
    userAvatar: document.getElementById('userAvatar'),
    userName: document.getElementById('userName'),
    themeToggle: document.getElementById('themeToggle'),
    toggleBtn: document.getElementById('toggleBtn'),
    radialMenu: document.getElementById('radialMenu'),
    innerCircle: document.getElementById('innerCircle'),
    moduleSelector: document.getElementById('moduleSelector'),
    empMenu: document.getElementById('empMenu'),
    hrMenu: document.getElementById('hrMenu'),
    mainContent: document.getElementById('mainContent'),
    searchInput: document.getElementById('searchInput'),
    searchButton: document.getElementById('searchButton'),
    searchBar: document.getElementById('searchBar'),
    autocompleteDropdown: document.getElementById('autocompleteDropdown')
  };

  const state = {
    user: null,
    token: null,
    refreshToken: null,
    isDarkMode: false,
    isAuthenticated: false,
    isToggling: false,
    currentMenu: 'emp',
    personnelDetails: null,
    ws: null
  };

  const wsClient = {
    connect: () => {
      state.ws = new WebSocket(config.wsUrl);
      
      state.ws.onopen = () => {
        console.log('WebSocket connection established');
      };

      state.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'employeeDetails') {
            state.personnelDetails = data.details;
            try {
              localStorage.setItem('abccompanyempdetails', JSON.stringify(data.details));
              wsClient.populateFormFields(data.details);
            } catch (storageError) {
              console.error('Failed to save to localStorage:', storageError);
            }
          }
        } catch (error) {
          console.error('WebSocket message error:', error);
        }
      };

      state.ws.onclose = () => {
        console.log('WebSocket connection closed, attempting to reconnect...');
        setTimeout(wsClient.connect, 5000);
      };

      state.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
    },

    sendEmployeeDetails: (details) => {
      if (state.ws && state.ws.readyState === WebSocket.OPEN) {
        state.ws.send(JSON.stringify({
          type: 'employeeDetails',
          details: {
            name: details.name,
            email: details.email,
            emp_id: details.emp_id
          }
        }));
      }
    },

    populateFormFields: (details) => {
      const fields = {
        'name': details.name,
        'email': details.email,
        'emp_id': details.emp_id,
        'employeeId': details.emp_id
      };

      Object.entries(fields).forEach(([fieldName, value]) => {
        const input = document.querySelector(`input[name="${fieldName}"], input[id="${fieldName}"]`);
        if (input) {
          input.value = value || '';
        }
      });
    }
  };

  const utils = {
    showAlert: (type, message) => {
      const alert = document.createElement('div');
      alert.className = `alert ${type}`;
      const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
      };
      alert.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i> ${message}`;
      document.body.appendChild(alert);
      setTimeout(() => {
        alert.style.animation = 'slideOutRight 0.5s ease-out forwards';
        setTimeout(() => alert.remove(), 500);
      }, 3000);
    },

    handleApiError: (error) => {
      console.error('API Error:', error);
      utils.showAlert('error', error.message || 'An error occurred');
      if (error.status === 401) {
        core.verifySession();
      }
    },

    getCookie: (name) => {
      const value = `; ${document.cookie}`;
      const parts = value.split(`; ${name}=`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    },

    fetchWithAuth: async (url, options = {}) => {
      try {
        let token = utils.getCookie('accessToken') || state.token;
        if (!token) {
          throw { status: 401, message: 'No authentication token found' };
        }

        const response = await fetch(`${config.apiBaseUrl}${url}`, {
          ...options,
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...options.headers
          },
          credentials: 'include'
        });

        if (!response.ok) {
          const errorData = await response.json();
          if (response.status === 401 && state.refreshToken) {
            const refreshResponse = await fetch(`${config.apiBaseUrl}/refresh`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ refreshToken: state.refreshToken }),
              credentials: 'include'
            });

            if (refreshResponse.ok) {
              const { accessToken } = await refreshResponse.json();
              document.cookie = `accessToken=${accessToken}; maxAge=900; path=/`;
              state.token = accessToken;
              options.headers = { ...options.headers, 'Authorization': `Bearer ${accessToken}` };
              return await fetch(`${config.apiBaseUrl}${url}`, options);
            }
          }
          throw {
            status: response.status,
            message: errorData.error || 'Request failed'
          };
        }

        return await response.json();
      } catch (error) {
        utils.handleApiError(error);
        throw error;
      }
    }
  };

  const core = {
    showLoginView: () => {
      elements.appBody.classList.add('login-body');
      elements.loginView.classList.remove('hidden');
      elements.dashboardView.classList.add('hidden');
      elements.emailInput.focus();
      wsClient.connect();
    },

    showDashboardView: () => {
      elements.appBody.classList.remove('login-body');
      elements.loginView.classList.add('hidden');
      elements.dashboardView.classList.remove('hidden');
      core.initTheme();
      core.initNavigation();
      core.initSessionChecker();
      wsClient.connect();
    },

    verifySession: async () => {
      const token = utils.getCookie('accessToken') || state.token;
      const refreshToken = utils.getCookie('refreshToken') || state.refreshToken;

      if (!token && !refreshToken) {
        state.isAuthenticated = false;
        core.showLoginView();
        return false;
      }

      try {
        const response = await utils.fetchWithAuth('/profile');
        state.user = response.profile;
        state.personnelDetails = response.personnel || null;

        if (state.personnelDetails) {
          try {
            localStorage.setItem('abccompanyempdetails', JSON.stringify(state.personnelDetails));
            wsClient.sendEmployeeDetails(state.personnelDetails);
            wsClient.populateFormFields(state.personnelDetails);
          } catch (storageError) {
            console.error('Failed to save to localStorage:', storageError);
          }
        } else {
          localStorage.removeItem('abccompanyempdetails');
        }

        state.token = token;
        state.isAuthenticated = true;

        setTimeout(() => {
          elements.avatarSkeleton.style.display = 'none';
          elements.userAvatar.style.display = 'block';
          elements.userAvatar.src = state.user.profile_image ||
            'https://img.icons8.com/fluency/48/user-male-circle.png';
          elements.userName.textContent = state.user.username || 'User';
          elements.userName.style.opacity = 0;
          setTimeout(() => {
            elements.userName.style.transition = 'opacity 0.3s ease';
            elements.userName.style.opacity = 1;
          }, 50);
        }, 800);

        core.showDashboardView();
        return true;
      } catch (error) {
        if (refreshToken && error.status === 401) {
          try {
            const refreshResponse = await fetch(`${config.apiBaseUrl}/refresh`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ refreshToken }),
              credentials: 'include'
            });

            if (refreshResponse.ok) {
              const { accessToken } = await refreshResponse.json();
              document.cookie = `accessToken=${accessToken}; maxAge=900; path=/`;
              state.token = accessToken;
              return await core.verifySession();
            }
          } catch (refreshError) {
            console.error('Refresh token failed:', refreshError);
          }
        }
        localStorage.removeItem('abccompanyempdetails');
        sessionStorage.removeItem('user');
        document.cookie = 'accessToken=; Max-Age=0; path=/;';
        document.cookie = 'refreshToken=; Max-Age=0; path=/;';
        state.isAuthenticated = false;
        state.user = null;
        state.token = null;
        state.refreshToken = null;
        state.personnelDetails = null;
        core.showLoginView();
        return false;
      }
    },

    initTheme: () => {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      const savedTheme = localStorage.getItem('theme');
      state.isDarkMode = savedTheme === 'dark' || (!savedTheme && prefersDark);
      if (state.isDarkMode) {
        document.body.classList.add('dark-mode');
        elements.themeToggle.innerHTML = '<i class="material-icons">light_mode</i>';
      } else {
        elements.themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
      }

      elements.themeToggle.addEventListener('click', () => {
        state.isDarkMode = !state.isDarkMode;
        document.body.classList.toggle('dark-mode');
        elements.themeToggle.innerHTML = state.isDarkMode
          ? '<i class="material-icons">light_mode</i>'
          : '<i class="fas fa-moon"></i>';
        localStorage.setItem('theme', state.isDarkMode ? 'dark' : 'light');
      });
    },

    initNavigation: () => {
      const positionMenuItems = (menu, numItems) => {
        const radius = 150;
        const angleStep = 360 / numItems;
        menu.querySelectorAll('.menu-item').forEach((item, index) => {
          const angle = index * angleStep - 90;
          const rad = angle * (Math.PI / 180);
          const x = radius * Math.cos(rad);
          const y = radius * Math.sin(rad);
          item.style.left = `calc(50% + ${x}px - 20px)`;
          item.style.top = `calc(50% + ${y}px - 20px)`;
        });
      };

      positionMenuItems(elements.empMenu, elements.empMenu.querySelectorAll('.menu-item').length);
      positionMenuItems(elements.hrMenu, elements.hrMenu.querySelectorAll('.menu-item').length);

      const showMenu = (menuType) => {
        elements.empMenu.classList.remove('active');
        elements.hrMenu.classList.remove('active');
        if (menuType === 'emp') {
          elements.empMenu.classList.add('active');
        } else if (menuType === 'hr') {
          elements.hrMenu.classList.add('active');
        }
        state.currentMenu = menuType;
        elements.moduleSelector.value = menuType;
      };

      elements.moduleSelector.addEventListener('change', (event) => {
        event.stopPropagation();
        const module = event.target.value;
        showMenu(module);
      });

      [elements.empMenu, elements.hrMenu].forEach(menu => {
        menu.querySelectorAll('.menu-item').forEach(item => {
          item.addEventListener('click', (event) => {
            event.stopPropagation();
            const module = item.dataset.module;
            if (module === 'emp_logout' || module === 'hr_logout') {
              core.handleLogout();
              return;
            }
            if (config.modules[module]) {
              elements.contentFrame.style.opacity = '0.5';
              elements.contentFrame.style.transition = 'opacity 0.3s ease';
              setTimeout(() => {
                elements.contentFrame.src = config.modules[module];
                elements.contentFrame.onload = () => {
                  elements.contentFrame.style.opacity = '1';
                };
              }, 200);
            } else {
              utils.showAlert('error', `Module ${module} not found`);
            }
            elements.radialMenu.classList.add('closing');
            elements.radialMenu.classList.remove('active');
            document.body.classList.remove('menu-open');
            showMenu('emp');
            setTimeout(() => {
              elements.radialMenu.classList.remove('closing');
              elements.toggleBtn.disabled = false;
              state.isToggling = false;
            }, 1000);
          });
        });
      });

      elements.toggleBtn.addEventListener('click', (event) => {
        event.stopPropagation();
        if (state.isToggling) return;
        state.isToggling = true;
        elements.toggleBtn.disabled = true;
        elements.radialMenu.classList.toggle('active');
        document.body.classList.toggle('menu-open');
        if (elements.radialMenu.classList.contains('active')) {
          showMenu('emp');
        } else {
          elements.radialMenu.classList.add('closing');
          setTimeout(() => {
            elements.radialMenu.classList.remove('closing');
            elements.toggleBtn.disabled = false;
            state.isToggling = false;
          }, 1000);
        }
        setTimeout(() => {
          elements.toggleBtn.disabled = false;
          state.isToggling = false;
        }, 1000);
      });

      document.addEventListener('click', (event) => {
        if (elements.radialMenu.classList.contains('active') &&
            !elements.radialMenu.contains(event.target) &&
            !elements.toggleBtn.contains(event.target)) {
          if (state.isToggling) return;
          state.isToggling = true;
          elements.toggleBtn.disabled = true;
          elements.radialMenu.classList.add('closing');
          elements.radialMenu.classList.remove('active');
          document.body.classList.remove('menu-open');
          showMenu('emp');
          setTimeout(() => {
            elements.radialMenu.classList.remove('closing');
            elements.toggleBtn.disabled = false;
            state.isToggling = false;
          }, 1000);
        }
        if (!elements.searchBar.contains(event.target)) {
          elements.autocompleteDropdown.style.display = 'none';
        }
      });

      elements.moduleSelector.addEventListener('click', (event) => {
        event.stopPropagation();
      });

      const moduleNames = {
        emp_attendance: { name: 'Attendance', icon: 'https://img.icons8.com/color/24/calendar--v1.png' },
        emp_leave: { name: 'Leave', icon: 'https://img.icons8.com/color/24/beach.png' },
        emp_wfh: { name: 'WFH', icon: 'https://img.icons8.com/color/24/laptop.png' },
        emp_payslip: { name: 'Payslip', icon: 'https://img.icons8.com/color/24/money-bag.png' },
        emp_tasks: { name: 'Tasks', icon: 'https://img.icons8.com/color/24/task-completed.png' },
        emp_helpdesk: { name: 'Help Desk', icon: 'https://img.icons8.com/color/24/help.png' },
        emp_Onboarding: { name: 'Onboarding', icon: 'https://cdn-icons-png.freepik.com/256/13730/13730909.png?semt=ais_hybrid' },
        emp_benefits: { name: 'Benefits', icon: 'https://cdn-icons-png.flaticon.com/512/8655/8655563.png' },
        emp_Appraisal: { name: 'Appraisal', icon: 'https://cdn-icons-png.flaticon.com/512/12278/12278438.png' },
        emp_notifications: { name: 'Notifications', icon: 'https://cdn-icons-png.flaticon.com/512/4658/4658755.png' },
        emp_asset: { name: 'Assets', icon: 'https://cdn-icons-png.flaticon.com/512/3135/3135771.png' },
        emp_bonus: { name: 'Bonus', icon: 'https://cdn-icons-png.flaticon.com/512/6303/6303173.png' },
        emp_joblists: { name: 'Job Listings', icon: 'https://cdn-icons-png.flaticon.com/512/4116/4116684.png' },
        emp_claim: { name: 'Claims', icon: 'https://cdn-icons-png.flaticon.com/512/12194/12194787.png' },
        emp_offboarding: { name: 'Offboarding', icon: 'https://cdn-icons-png.freepik.com/256/8265/8265009.png?semt=ais_hybrid' },
        emp_jobapplication: { name: 'Job Application', icon: 'https://cdn-icons-png.flaticon.com/512/13441/13441753.png' },
        emp_offerletter: { name: 'Offer Letter', icon: 'https://cdn-icons-png.freepik.com/256/4654/4654143.png?semt=ais_hybrid' },
        hr_attendance: { name: 'Attendance', icon: 'https://img.icons8.com/color/24/calendar--v1.png' },
        hr_leave: { name: 'Leave', icon: 'https://img.icons8.com/color/24/beach.png' },
        hr_wfh: { name: 'WFH', icon: 'https://img.icons8.com/color/24/laptop.png' },
        hr_payslip: { name: 'Payslip', icon: 'https://img.icons8.com/color/24/money-bag.png' },
        hr_tasks: { name: 'Tasks', icon: 'https://img.icons8.com/color/24/task-completed.png' },
        hr_helpdesk: { name: 'Help Desk', icon: 'https://img.icons8.com/color/24/help.png' },
        hr_employeemanagement: { name: 'Employee Management', icon: 'https://img.icons8.com/color/24/conference-call.png' },
        hr_benefits: { name: 'Benefits', icon: 'https://cdn-icons-png.flaticon.com/512/11113/11113093.png' },
        hr_appraisal: { name: 'Appraisal', icon: 'https://cdn-icons-png.flaticon.com/512/11112/11112856.png' },
        hr_notifications: { name: 'Notifications', icon: 'https://img.icons8.com/color/24/appointment-reminders.png' },
        hr_asset: { name: 'Assets', icon: 'https://img.icons8.com/color/24/feedback.png' },
        hr_bonus: { name: 'Bonus', icon: 'https://img.icons8.com/color/24/document.png' },
        hr_joblists: { name: 'Job Listings', icon: 'https://img.icons8.com/color/24/training.png' },
        hr_claim: { name: 'Claims', icon: 'https://cdn-icons-png.freepik.com/256/14252/14252153.png?semt=ais_hybrid' },
        hr_offboarding: { name: 'Offboarding', icon: 'https://img.icons8.com/?size=192&id=E1XHpaUoWFxv&format=png' },
        hr_jobapplication: { name: 'Job Application', icon: 'https://cdn-icons-png.flaticon.com/512/16995/16995294.png' },
        hr_Onboarding: { name: 'Onboarding', icon: 'https://cdn-icons-png.flaticon.com/512/3862/3862949.png' }
      };

      const performSearch = (query) => {
        if (query.length < 3) {
          elements.autocompleteDropdown.style.display = 'none';
          return;
        }
        elements.autocompleteDropdown.innerHTML = '';
        const results = Object.entries(moduleNames).filter(([key, module]) =>
          module.name.toLowerCase().includes(query.toLowerCase())
        );
        if (results.length === 0) {
          const noResults = document.createElement('div');
          noResults.className = 'no-results';
          noResults.textContent = 'No module found';
          elements.autocompleteDropdown.appendChild(noResults);
          elements.autocompleteDropdown.style.display = 'block';
          return;
        }
        results.forEach(([moduleKey, module]) => {
          const item = document.createElement('div');
          item.className = 'autocomplete-item';
          item.innerHTML = `<img src="${module.icon}" alt="${module.name}"><span>${module.name}</span>`;
          item.dataset.module = moduleKey;
          item.addEventListener('click', () => {
            if (config.modules[moduleKey]) {
              elements.contentFrame.style.opacity = '0.5';
              elements.contentFrame.style.transition = 'opacity 0.3s ease';
              setTimeout(() => {
                elements.contentFrame.src = config.modules[moduleKey];
                elements.contentFrame.onload = () => {
                  elements.contentFrame.style.opacity = '1';
                };
              }, 200);
              elements.autocompleteDropdown.style.display = 'none';
              elements.searchInput.value = '';
            } else {
              utils.showAlert('error', `Module ${module.name} not found`);
            }
          });
          elements.autocompleteDropdown.appendChild(item);
        });
        elements.autocompleteDropdown.style.display = 'block';
      };

      elements.searchInput.addEventListener('input', (event) => {
        performSearch(event.target.value.trim());
      });

      elements.searchButton.addEventListener('click', () => {
        performSearch(elements.searchInput.value.trim());
      });

      elements.searchInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
          performSearch(elements.searchInput.value.trim());
        }
      });
    },

    initSessionChecker: () => {
      setInterval(async () => {
        if (state.isAuthenticated) {
          await core.verifySession();
        }
      }, config.sessionCheckInterval);
    },

    handleLogout: () => {
      fetch(`${config.apiBaseUrl}/logout`, {
        method: 'POST',
        credentials: 'include'
      })
      .then(() => {
        if (state.ws) {
          state.ws.close();
        }
        localStorage.removeItem('abccompanyempdetails');
        sessionStorage.removeItem('user');
        document.cookie = 'accessToken=; Max-Age=0; path=/;';
        document.cookie = 'refreshToken=; Max-Age=0; path=/;';
        state.isAuthenticated = false;
        state.user = null;
        state.token = null;
        state.refreshToken = null;
        state.personnelDetails = null;
        utils.showAlert('success', 'Logged out successfully');
        core.showLoginView();
      })
      .catch(err => {
        utils.handleApiError(err);
      });
    },

    validateForm: () => {
      const email = elements.emailInput.value.trim();
      const password = elements.passwordInput.value;
      elements.errorMessage.textContent = '';
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!email) {
        elements.errorMessage.textContent = 'Email is required';
        return false;
      }
      if (!emailRegex.test(email)) {
        elements.errorMessage.textContent = 'Invalid email format';
        return false;
      }
      if (!password) {
        elements.errorMessage.textContent = 'Password is required';
        return false;
      }
      if (password.length < 8) {
        elements.errorMessage.textContent = 'Password must be at least 8 characters';
        return false;
      }

      return true;
    },

    handleLogin: async (e) => {
      e.preventDefault();
      if (!core.validateForm()) return;

      const email = elements.emailInput.value.trim();
      const password = elements.passwordInput.value;
      elements.loginButton.disabled = true;
      elements.loginButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';

      try {
        const response = await fetch(`${config.apiBaseUrl}/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
          if (data.accessToken) {
            document.cookie = `accessToken=${data.accessToken}; maxAge=900; path=/`;
            state.token = data.accessToken;
          }
          if (data.refreshToken) {
            document.cookie = `refreshToken=${data.refreshToken}; maxAge=604800; path=/`;
            state.refreshToken = data.refreshToken;
          }
          if (data.user) {
            sessionStorage.setItem('user', JSON.stringify(data.user));
            state.user = data.user;
          }
          if (data.personnel) {
            try {
              localStorage.setItem('abccompanyempdetails', JSON.stringify(data.personnel));
              state.personnelDetails = data.personnel;
              wsClient.sendEmployeeDetails(data.personnel);
              wsClient.populateFormFields(data.personnel);
            } catch (storageError) {
              console.error('Failed to save personnel details:', storageError);
            }
          }
          state.isAuthenticated = true;
          utils.showAlert('success', 'Login successful! Redirecting...');
          await core.verifySession();
        } else {
          elements.errorMessage.textContent = data.error || 'Login failed';
          utils.showAlert('error', data.error || 'Login failed');
          elements.passwordInput.value = '';
        }
      } catch (err) {
        elements.errorMessage.textContent = 'Error connecting to server';
        utils.showAlert('error', 'Error connecting to server');
      } finally {
        elements.loginButton.disabled = false;
        elements.loginButton.textContent = 'Login';
      }
    },

    togglePassword: () => {
      if (elements.passwordInput.type === 'password') {
        elements.passwordInput.type = 'text';
        elements.eyeIcon.innerHTML = '<i class="fas fa-eye-slash"></i>';
      } else {
        elements.passwordInput.type = 'password';
        elements.eyeIcon.innerHTML = '<i class="fas fa-eye"></i>';
      }
    }
  };

  const init = async () => {
    const savedPersonnel = localStorage.getItem('abccompanyempdetails');
    if (savedPersonnel) {
      try {
        state.personnelDetails = JSON.parse(savedPersonnel);
        wsClient.populateFormFields(state.personnelDetails);
      } catch (error) {
        console.error("Failed to parse saved personnel details:", error);
      }
    }

    const isAuthenticated = await core.verifySession();
    if (isAuthenticated) {
      utils.showAlert('success', `Welcome back, ${state.user.username || 'User'}!`);
    } else {
      core.showLoginView();
      elements.eyeIcon.addEventListener('click', core.togglePassword);
      elements.loginForm.addEventListener('submit', core.handleLogin);
    }
  };

  init();
});
